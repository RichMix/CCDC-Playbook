#!/usr/bin/env bash
#===============================================================================
# harden-linux.sh  --  Portable Linux hardening + persistence-hunt playbook
#-------------------------------------------------------------------------------
# Runs on RHEL-family (Rocky/Alma/CentOS/Fedora/RHEL), Debian-family
# (Debian/Ubuntu/Mint), and Arch-family (Arch/Manjaro). Detects the distro
# family and swaps the four subsystems that differ between them:
#
#     subsystem    RHEL family        Debian family        Arch family
#     ---------    ----------------   ------------------   -----------------
#     packages     dnf / rpm          apt / dpkg           pacman
#     firewall     firewalld          ufw (or nftables)    nftables / iptables
#     MAC          SELinux            AppArmor             none (optional)
#     web server   httpd              apache2              httpd
#
# Everything else -- the persistence hunt, backups, dry-run gate, egress
# control, audit watches, and the tripwire timer -- is identical across
# families because they all use systemd, OpenSSH, cron, and /etc the same way.
#
# WHAT THIS DOES, IN ORDER:
#   0. Detect OS family + available firewall/MAC tooling.
#   1. INVENTORY: snapshot state to a baseline you can diff later.
#   2. HUNT: surface attacker persistence (keys, users, cron, systemd,
#            bashrc, suid, listeners, webshells). Reports -- never auto-nukes.
#   3. HARDEN: SSH, accounts, firewall+egress, MAC, sysctl, web/PHP/DB,
#              logging. Each step branches per family.
#   4. WATCH: install a systemd-timer tripwire that logs new persistence.
#
# SAFETY:
#   * NOTHING changes without --apply. Default is report-only (dry-run).
#   * Every edited file is backed up under $BACKUP first (one cp = rollback).
#   * ICMP echo is left UP and inbound scored services stay open to all
#     sources -- the egress direction is where we clamp down, so a reverse
#     shell can't dial out even if something gets popped.
#
# USAGE:
#   sudo ./harden-linux.sh                        # dry-run: hunt + report
#   sudo ./harden-linux.sh --apply                # apply hardening
#   sudo ./harden-linux.sh --apply --ssh-key "ssh-ed25519 AAAA... you@host"
#   sudo ./harden-linux.sh --hunt-only            # persistence hunt only
#   sudo ./harden-linux.sh --force-family debian  # override autodetect
#===============================================================================

set -uo pipefail   # -u catch unset vars, pipefail propagate pipe errors.
                   # NOT -e: one failed probe must not abort the whole pass.

#------------------------------------------------------------------------------
# 0a. Arg parsing
#------------------------------------------------------------------------------
APPLY=0                        # 0 = report only, 1 = make changes
HUNT_ONLY=0                    # 1 = run hunt then exit
SSH_PUBKEY=""                  # optional authorized key to install
ADMIN_USER="${SUDO_USER:-}"    # human who ran sudo; keeps SSH access
FORCE_FAMILY=""                # override detection: rhel|debian|arch

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)         APPLY=1 ;;
    --hunt-only)     HUNT_ONLY=1 ;;
    --ssh-key)       SSH_PUBKEY="${2:-}"; shift ;;   # next arg = the pubkey
    --admin)         ADMIN_USER="${2:-}"; shift ;;   # who keeps SSH access
    --force-family)  FORCE_FAMILY="${2:-}"; shift ;; # skip autodetect
    -h|--help)       grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

# Must be root -- nearly every action reads/writes root-owned paths.
if [[ "$(id -u)" -ne 0 ]]; then
  echo "[!] run as root (sudo)." >&2; exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"            # single timestamp for this run
WORKDIR="/root/harden-${TS}"           # all artifacts land here
BACKUP="${WORKDIR}/backup"             # pre-change copies (rollback source)
BASELINE="${WORKDIR}/baseline"        # inventory snapshots (diff later)
LOG="${WORKDIR}/run.log"              # full transcript
mkdir -p "$BACKUP" "$BASELINE"

# --- logging helpers: print to screen AND append to the run log -------------
log()  { echo -e "$*" | tee -a "$LOG"; }
hdr()  { log "\n\033[1;36m==== $* ====\033[0m"; }   # cyan  section header
ok()   { log "  \033[1;32m[ok]\033[0m  $*"; }       # green good
warn() { log "  \033[1;33m[!!]\033[0m  $*"; }       # amber look here
bad()  { log "  \033[1;31m[XX]\033[0m  $*"; }       # red  probable attacker
act()  { log "  \033[1;34m[>>]\033[0m  $*"; }       # blue action taken

# backup_file <path>: mirror a file into $BACKUP before we edit it.
backup_file() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  local dest="${BACKUP}${f}"            # preserve the absolute path under BACKUP
  mkdir -p "$(dirname "$dest")"
  cp -a "$f" "$dest" 2>/dev/null && act "backed up $f"
}

# run_change <desc> <cmd...>: honor dry-run vs --apply.
run_change() {
  local desc="$1"; shift
  if [[ "$APPLY" -eq 1 ]]; then
    act "$desc"
    "$@" >>"$LOG" 2>&1 || warn "   ^ command returned non-zero (see $LOG)"
  else
    log "  \033[2m[dry-run] would: $desc\033[0m"
  fi
}

#------------------------------------------------------------------------------
# 0b. OS-FAMILY + TOOLING DETECTION  -- this is what makes the script portable
#------------------------------------------------------------------------------
detect_platform() {
  hdr "0. PLATFORM DETECTION"

  # /etc/os-release is the cross-distro source of truth. ID is the distro;
  # ID_LIKE lists the families it derives from (e.g. rocky -> "rhel centos fedora").
  local id="" like=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    id="${ID:-}"; like="${ID_LIKE:-}"
  fi

  if [[ -n "$FORCE_FAMILY" ]]; then
    FAMILY="$FORCE_FAMILY"                       # operator override wins
  else
    # Match against ID + ID_LIKE together so derivatives map to their parent.
    case " ${id} ${like} " in
      *rhel*|*fedora*|*centos*) FAMILY="rhel" ;;
      *debian*|*ubuntu*)        FAMILY="debian" ;;
      *arch*)                   FAMILY="arch" ;;
      *) # ID_LIKE was empty/unknown -- fall back to the bare ID
         case "$id" in
           rocky|almalinux|rhel|centos|fedora)      FAMILY="rhel" ;;
           debian|ubuntu|linuxmint|pop|raspbian)    FAMILY="debian" ;;
           arch|manjaro|endeavouros|garuda|cachyos) FAMILY="arch" ;;
           *) FAMILY="unknown" ;;
         esac ;;
    esac
  fi

  # Per-family package-manager handles used by the rest of the script.
  case "$FAMILY" in
    rhel)
      PM_INSTALL="dnf install -y"
      PM_RECENT()  { rpm -qa --last | head -40; }                       # newest RPMs
      WEB_SVCS="httpd nginx php-fpm" ;;
    debian)
      export DEBIAN_FRONTEND=noninteractive                             # no apt prompts
      PM_INSTALL="apt-get install -y"
      PM_RECENT()  { grep -h ' install ' /var/log/dpkg.log* 2>/dev/null | tail -40; }
      WEB_SVCS="apache2 nginx php-fpm" ;;
    arch)
      PM_INSTALL="pacman -S --noconfirm"
      PM_RECENT()  { grep -i 'installed\|upgraded' /var/log/pacman.log 2>/dev/null | tail -40; }
      WEB_SVCS="httpd nginx php-fpm" ;;
    *)
      PM_INSTALL="echo (no package manager mapped for family=$FAMILY) "
      PM_RECENT()  { echo "(unknown family -- no package history mapping)"; }
      WEB_SVCS="httpd apache2 nginx php-fpm" ;;
  esac

  # Firewall backend: pick the first that's actually present. Order reflects
  # each family's default, but we probe rather than assume.
  if   command -v firewall-cmd >/dev/null 2>&1; then FW="firewalld"
  elif command -v ufw          >/dev/null 2>&1; then FW="ufw"
  elif command -v nft          >/dev/null 2>&1; then FW="nftables"
  elif command -v iptables     >/dev/null 2>&1; then FW="iptables"
  else FW="none"; fi

  # Mandatory Access Control layer present on this host.
  if   command -v getenforce >/dev/null 2>&1; then MAC="selinux"
  elif command -v aa-status  >/dev/null 2>&1; then MAC="apparmor"
  else MAC="none"; fi

  log "  distro ID    : ${id:-unknown}   (ID_LIKE: ${like:-none})"
  log "  OS family    : $FAMILY"
  log "  firewall     : $FW"
  log "  MAC layer    : $MAC"
  log "  mode         : $([[ $APPLY -eq 1 ]] && echo APPLY || echo DRY-RUN)"
  [[ -n "$ADMIN_USER" ]] && log "  admin user   : $ADMIN_USER (keeps SSH)"
  [[ "$FAMILY" == "unknown" ]] && \
    warn "family not recognized -- hunt still works; harden steps may skip. Use --force-family."
}

#------------------------------------------------------------------------------
# 1. INVENTORY -- snapshot state so you can diff after an intruder pokes the box
#------------------------------------------------------------------------------
inventory() {
  hdr "1. INVENTORY / BASELINE"
  ps auxww                           > "${BASELINE}/processes.txt" 2>&1
  ss -tulpnH                         > "${BASELINE}/listeners.txt" 2>&1
  ss -tnpH state established         > "${BASELINE}/connections.txt" 2>&1
  getent passwd                      > "${BASELINE}/passwd.txt" 2>&1   # incl. LDAP/SSSD
  getent group                       > "${BASELINE}/group.txt" 2>&1
  systemctl list-unit-files --type=service > "${BASELINE}/services.txt" 2>&1
  systemctl list-timers --all        > "${BASELINE}/timers.txt" 2>&1
  crontab -l 2>/dev/null             > "${BASELINE}/crontab-root.txt"
  PM_RECENT                          > "${BASELINE}/recent-packages.txt" 2>&1
  # Hash every system binary dir -- compare later to catch trojaned binaries.
  find /usr/bin /usr/sbin /bin /sbin -type f -exec sha256sum {} + \
      > "${BASELINE}/bin-hashes.txt" 2>/dev/null
  ok "baseline written to $BASELINE (diff against this after suspicious activity)"
}

#------------------------------------------------------------------------------
# 2. HUNT -- surface persistence. Distro-agnostic: systemd/cron/ssh/passwd are
#            the same everywhere. Reports only; you decide what's legit.
#------------------------------------------------------------------------------
hunt() {
  hdr "2. PERSISTENCE HUNT (review before removing anything)"

  # --- 2a. Rogue / backdoor accounts ----------------------------------------
  log "\n-- UID 0 accounts (only 'root' should appear):"
  awk -F: '$3==0 {print "    "$1}' /etc/passwd | tee -a "$LOG"
  local uid0; uid0=$(awk -F: '$3==0' /etc/passwd | wc -l)
  [[ "$uid0" -gt 1 ]] && bad "more than one UID-0 account -> BACKDOOR" \
      || ok "exactly one UID-0 account"

  log "\n-- accounts with interactive shells, UID>=1000 (verify each is yours):"
  awk -F: '$7 ~ /(bash|sh|zsh)$/ && $3>=1000 {print "    "$1" (uid "$3", "$7")"}' \
      /etc/passwd | tee -a "$LOG"

  # sudo group differs by family: 'wheel' on RHEL/Arch, 'sudo' on Debian.
  local sudogrp="wheel"; [[ "$FAMILY" == "debian" ]] && sudogrp="sudo"
  log "\n-- sudo-capable (${sudogrp} group + sudoers.d drop-ins):"
  getent group "$sudogrp" | tee -a "$LOG"
  grep -rEl 'ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while read -r f; do
    log "    sudoers file: $f"; grep -vE '^\s*#|^\s*$' "$f" | sed 's/^/        /'
  done

  # --- 2b. SSH key persistence (the #1 quiet backdoor) ----------------------
  log "\n-- authorized_keys across all homes + root (fingerprint each):"
  { echo "/root"; awk -F: '$3>=1000{print $6}' /etc/passwd; } | sort -u | \
  while read -r home; do
    for akf in "$home"/.ssh/authorized_keys "$home"/.ssh/authorized_keys2; do
      [[ -f "$akf" ]] || continue
      warn "keys in $akf:"
      while read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        echo "$line" | ssh-keygen -lf - 2>/dev/null | sed 's/^/        /' | tee -a "$LOG"
      done < "$akf"
    done
  done

  # --- 2c. Cron + systemd timers --------------------------------------------
  log "\n-- per-user crontabs:"
  for u in $(cut -d: -f1 /etc/passwd); do
    local ct; ct=$(crontab -l -u "$u" 2>/dev/null)
    [[ -n "$ct" ]] && { warn "crontab for $u:"; echo "$ct" | sed 's/^/        /'; }
  done
  log "\n-- system cron locations with non-comment content:"
  for d in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily \
           /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
    [[ -e "$d" ]] && find "$d" -type f -exec grep -lvE '^\s*#' {} \; 2>/dev/null \
        | while read -r f; do warn "cron file: $f"; done
  done
  log "\n-- systemd timers:"
  systemctl list-timers --all --no-pager 2>/dev/null | sed 's/^/    /' | tee -a "$LOG"
  log "\n-- systemd unit files modified in the last 2 days (likely freshly planted):"
  find /etc/systemd/system /usr/lib/systemd/system /run/systemd/system \
       -name '*.service' -mtime -2 2>/dev/null | sed 's/^/    /' | tee -a "$LOG"

  # --- 2d. Shell init reverse shells ----------------------------------------
  log "\n-- shell init files referencing net tooling (nc / bash -i / curl|sh / python -c):"
  grep -rEl '(bash -i|nc |ncat |/dev/tcp/|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|python[0-9]* -c)' \
      /etc/profile /etc/profile.d /etc/bash.bashrc /etc/bashrc \
      /root/.bashrc /root/.bash_profile \
      /home/*/.bashrc /home/*/.bash_profile /home/*/.profile 2>/dev/null \
      | while read -r f; do bad "suspicious init file: $f"; done

  # --- 2e. SUID/SGID + capabilities -----------------------------------------
  log "\n-- SUID/SGID binaries OUTSIDE normal system dirs (classic drop spot):"
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
      > "${BASELINE}/suid-sgid.txt"
  grep -vE '^/(usr/bin|usr/sbin|bin|sbin|usr/lib|usr/lib64|usr/libexec)/' \
      "${BASELINE}/suid-sgid.txt" | while read -r f; do bad "odd-location SUID: $f"; done
  log "\n-- files with capabilities set (cap_setuid on an interpreter = privesc):"
  command -v getcap >/dev/null 2>&1 && getcap -r / 2>/dev/null | sed 's/^/    /' | tee -a "$LOG"

  # --- 2f. Listeners + webshells --------------------------------------------
  log "\n-- listening sockets (map each to an expected service):"
  ss -tulpn | sed 's/^/    /' | tee -a "$LOG"
  log "\n-- webroot scan for PHP shell patterns:"
  for wr in /var/www /usr/share/nginx/html /srv/www /srv/http; do
    [[ -d "$wr" ]] || continue
    grep -rEln --include='*.php' \
      -e 'eval *(' -e 'base64_decode *(' -e 'system *(' -e 'shell_exec *(' \
      -e 'passthru *(' -e 'assert *(' -e '\$_\(GET\|POST\|REQUEST\).*\(system\|exec\|eval\)' \
      "$wr" 2>/dev/null | while read -r f; do bad "possible webshell: $f"; done
  done

  # --- 2g. LD_PRELOAD userland rootkit --------------------------------------
  log "\n-- /etc/ld.so.preload (should NOT exist):"
  [[ -s /etc/ld.so.preload ]] && bad "ld.so.preload present: $(cat /etc/ld.so.preload)" \
      || ok "no ld.so.preload"

  ok "hunt complete -- chase the red items first"
}

#------------------------------------------------------------------------------
# 3a. SSH  -- identical across families; OpenSSH reads the same config.
#------------------------------------------------------------------------------
harden_ssh() {
  hdr "3a. SSH"
  # Modern Rocky 9 / Debian 12 / Arch all Include /etc/ssh/sshd_config.d/*.conf
  # and keep the FIRST value seen, so a LOW-numbered drop-in wins. Older boxes
  # (RHEL 8, old Debian) have no include -- we detect and fall back to the main file.
  local dropdir="/etc/ssh/sshd_config.d"
  local target
  if grep -qiE '^\s*Include\s+/etc/ssh/sshd_config\.d' /etc/ssh/sshd_config 2>/dev/null \
     && [[ -d "$dropdir" ]]; then
    target="${dropdir}/01-hardening.conf"     # 01- sorts before vendor 50-*
    ls -1 "$dropdir" 2>/dev/null | sed 's/^/    existing drop-in: /' | tee -a "$LOG"
  else
    target="/etc/ssh/sshd_config"             # no include dir -- edit main file
    warn "no sshd_config.d include -- writing into the main sshd_config"
  fi

  # Install your key + preserve the admin user's keys BEFORE killing passwords.
  if [[ "$APPLY" -eq 1 && -n "$SSH_PUBKEY" && -n "$ADMIN_USER" ]]; then
    local adminhome; adminhome=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
    install -d -m700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$adminhome/.ssh"
    backup_file "$adminhome/.ssh/authorized_keys"
    grep -qF "$SSH_PUBKEY" "$adminhome/.ssh/authorized_keys" 2>/dev/null \
      || echo "$SSH_PUBKEY" >> "$adminhome/.ssh/authorized_keys"
    chown "$ADMIN_USER":"$ADMIN_USER" "$adminhome/.ssh/authorized_keys"
    chmod 600 "$adminhome/.ssh/authorized_keys"
    act "installed your key for $ADMIN_USER"
  elif [[ -z "$SSH_PUBKEY" ]]; then
    warn "no --ssh-key given: keeping password auth ON to avoid lockout."
  fi

  local passauth="no"; [[ -z "$SSH_PUBKEY" ]] && passauth="yes"

  if [[ "$APPLY" -eq 1 ]]; then
    backup_file "$target"
    if [[ "$target" == *.d/* ]]; then
      # Drop-in: safe to overwrite our own file wholesale.
      cat > "$target" <<EOF
# hardening -- sorts before vendor defaults (sshd keeps the first value)
PermitRootLogin no
PasswordAuthentication ${passauth}
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
      [[ -n "$ADMIN_USER" ]] && echo "AllowUsers ${ADMIN_USER}" >> "$target"
      chmod 600 "$target"
    else
      # Main file: append a clearly-marked block instead of clobbering vendor config.
      { echo "# --- hardening block added $(date) ---"
        echo "PermitRootLogin no"
        echo "PasswordAuthentication ${passauth}"
        echo "PubkeyAuthentication yes"
        echo "PermitEmptyPasswords no"
        echo "MaxAuthTries 3"
      } >> "$target"
    fi
    # VALIDATE before reload -- a syntax error here can lose you the box.
    if sshd -t 2>>"$LOG"; then
      # service is 'sshd' on RHEL/Arch, 'ssh' on Debian -- reload whichever exists.
      systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null
      ok "sshd reloaded (PasswordAuthentication=${passauth})"
    else
      bad "sshd -t FAILED -- NOT reloaded. Fix $target before reloading."
    fi
  else
    log "  [dry-run] would write $target (PasswordAuthentication=${passauth}) + sshd -t + reload"
  fi
}

#------------------------------------------------------------------------------
# 3b. ACCOUNTS / CREDENTIALS  -- login.defs + pwquality exist on all families
#------------------------------------------------------------------------------
harden_accounts() {
  hdr "3b. ACCOUNTS / CREDENTIALS"
  log "  lock anything flagged in the hunt:  passwd -l <user> ; usermod -s /sbin/nologin <user>"

  if [[ -f /etc/login.defs ]]; then
    backup_file /etc/login.defs
    run_change "set password-aging defaults in login.defs" \
      sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/;s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
  fi

  # pwquality: RHEL ships libpwquality; Debian needs libpam-pwquality; Arch has it
  # if pam is built with it. We only write the conf if the file/dir is present.
  if [[ -f /etc/security/pwquality.conf ]]; then
    backup_file /etc/security/pwquality.conf
    run_change "enforce minlen=14 + complexity in pwquality.conf" \
      bash -c 'cat >/etc/security/pwquality.conf <<PWQ
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
PWQ'
  else
    warn "no pwquality.conf (install libpam-pwquality on Debian / libpwquality on Arch for policy)"
  fi

  log "\n  -- accounts with EMPTY password field (must be none):"
  awk -F: '($2==""){print "    "$1}' /etc/shadow | tee -a "$LOG"
}

#------------------------------------------------------------------------------
# 3c. FIREWALL + EGRESS  -- one goal, four backends. Inbound stays open to all;
#     we clamp EGRESS so a popped host can't call home. ICMP stays allowed.
#------------------------------------------------------------------------------
harden_firewall() {
  hdr "3c. FIREWALL + EGRESS CONTROL  (backend: $FW)"
  # Egress allowlist (same policy for every backend):
  #   out: loopback, established/related, DNS 53, NTP 123, HTTP 80, HTTPS 443, ICMP
  #   everything else outbound: log then drop.
  case "$FW" in

    firewalld)
      systemctl is-active firewalld >/dev/null 2>&1 || \
        run_change "enable+start firewalld" systemctl enable --now firewalld
      for s in http https ssh; do
        run_change "allow inbound $s (all sources)" \
          firewall-cmd --permanent --add-service="$s"
      done
      if [[ "$APPLY" -eq 1 ]]; then
        act "applying egress allowlist via firewalld direct rules"
        # NOTE: Rocky 9 firewalld uses the nftables backend; these iptables-style
        # --direct rules are translated into nft automatically. Verify after with:
        #   nft list ruleset
        firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -o lo -j ACCEPT
        firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 1 \
            -m state --state ESTABLISHED,RELATED -j ACCEPT
        for p in "udp 53" "tcp 53" "udp 123" "tcp 80" "tcp 443"; do
          set -- $p
          firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 2 \
              -p "$1" --dport "$2" -j ACCEPT
        done
        firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p icmp -j ACCEPT
        firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 10 \
            -j LOG --log-prefix "EGRESS-DROP: " --log-level 4
        firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 11 -j DROP
        firewall-cmd --reload && ok "firewalld reloaded; egress locked, inbound open"
      else
        log "  [dry-run] would open http/https/ssh + egress allowlist (DNS/NTP/80/443/icmp)"
      fi ;;

    ufw)
      # ufw (Debian/Ubuntu default). ufw auto-allows established replies, so we
      # just set default-deny outgoing and allow the specific egress ports.
      for s in 22 80 443; do
        run_change "ufw allow inbound $s" ufw allow "$s"
      done
      if [[ "$APPLY" -eq 1 ]]; then
        ufw --force enable >>"$LOG" 2>&1
        ufw default deny outgoing      >>"$LOG" 2>&1   # clamp egress
        ufw default allow incoming     >>"$LOG" 2>&1   # scored services open
        for rule in "53" "123" "80" "443"; do
          ufw allow out "$rule" >>"$LOG" 2>&1
        done
        # ufw allows ICMP via its before.rules by default -- leave it.
        ufw reload >>"$LOG" 2>&1 && ok "ufw: egress default-deny with DNS/NTP/80/443 out"
      else
        log "  [dry-run] would: ufw default deny outgoing + allow out 53/123/80/443"
      fi ;;

    nftables)
      # Standalone nftables (common on Arch). Add our OWN table so we don't
      # clobber existing rules; a drop in our output chain wins regardless of
      # other chains that accept.
      if [[ "$APPLY" -eq 1 ]]; then
        backup_file /etc/nftables.conf
        act "adding inet 'harden' egress table via nft"
        nft -f - <<'NFT'
table inet harden {
  chain egress {
    type filter hook output priority 0; policy accept;
    oif "lo" accept
    ct state established,related accept
    udp dport { 53, 123 } accept
    tcp dport { 53, 80, 443 } accept
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
    log prefix "EGRESS-DROP: "
    drop
  }
}
NFT
        # Persist so it survives reboot (append our table to nftables.conf).
        nft list table inet harden >> /etc/nftables.conf 2>/dev/null
        systemctl enable nftables >>"$LOG" 2>&1
        ok "nftables egress table applied (inbound untouched, ICMP allowed)"
      else
        log "  [dry-run] would add inet 'harden' egress chain (DNS/NTP/80/443/icmp out, drop rest)"
      fi ;;

    iptables)
      if [[ "$APPLY" -eq 1 ]]; then
        act "appending egress allowlist to iptables OUTPUT"
        iptables -A OUTPUT -o lo -j ACCEPT
        iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        for p in "udp 53" "tcp 53" "udp 123" "tcp 80" "tcp 443"; do
          set -- $p; iptables -A OUTPUT -p "$1" --dport "$2" -j ACCEPT
        done
        iptables -A OUTPUT -p icmp -j ACCEPT
        iptables -A OUTPUT -j LOG --log-prefix "EGRESS-DROP: "
        iptables -A OUTPUT -j DROP
        # Persist (path differs by distro); try the common savers.
        { iptables-save > /etc/iptables/rules.v4; } 2>/dev/null \
          || { iptables-save > /etc/sysconfig/iptables; } 2>/dev/null
        ok "iptables egress rules appended (persist path attempted)"
      else
        log "  [dry-run] would append OUTPUT allowlist (DNS/NTP/80/443/icmp) + DROP"
      fi ;;

    *)
      warn "no firewall tool detected -- install firewalld/ufw/nftables and re-run" ;;
  esac
  warn "if a SCORED service makes outbound calls (DB on another host, API), add"
  warn "its port to the egress allowlist above or that check will break."
}

#------------------------------------------------------------------------------
# 3d. MAC LAYER  -- SELinux (RHEL), AppArmor (Debian), or none (Arch default)
#------------------------------------------------------------------------------
harden_mac() {
  hdr "3d. MANDATORY ACCESS CONTROL  (layer: $MAC)"
  case "$MAC" in

    selinux)
      # SELinux enforcing is the single biggest anti-webshell control: even a
      # popped PHP process (httpd_t) can't open a reverse shell while
      # httpd_can_network_connect is off.
      local mode; mode=$(getenforce 2>/dev/null)
      log "  SELinux mode: $mode"
      if [[ "$mode" != "Enforcing" ]]; then
        bad "SELinux NOT enforcing -- re-enabling"
        run_change "setenforce 1" setenforce 1
        backup_file /etc/selinux/config
        run_change "persist SELINUX=enforcing" \
          sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
      else
        ok "SELinux enforcing"
      fi
      for b in httpd_can_network_connect httpd_can_network_connect_db \
               httpd_execmem httpd_enable_cgi httpd_tmp_exec; do
        local cur; cur=$(getsebool "$b" 2>/dev/null | awk '{print $3}')
        [[ "$cur" == "on" ]] && run_change "setsebool -P $b off (blocks web callback)" \
          setsebool -P "$b" off || ok "$b off"
      done
      warn "if the web app legitimately reaches a DB over the network, you may need"
      warn "httpd_can_network_connect_db back ON -- test the scored check after." ;;

    apparmor)
      # Debian/Ubuntu. No per-boolean web knobs like SELinux, but we can make
      # sure it's active and push any complain-mode profiles into enforce.
      run_change "enable+start apparmor" systemctl enable --now apparmor
      if [[ "$APPLY" -eq 1 ]]; then
        aa-status >>"$LOG" 2>&1
        # Flip every loaded profile from complain to enforce where possible.
        if command -v aa-enforce >/dev/null 2>&1; then
          aa-enforce /etc/apparmor.d/* >>"$LOG" 2>&1 || true
          ok "AppArmor profiles set to enforce where available"
        fi
      else
        log "  [dry-run] would enable apparmor + aa-enforce loaded profiles"
      fi
      warn "AppArmor has no httpd_can_network_connect equivalent -- rely on the"
      warn "egress firewall rules (3c) to stop web-process callbacks here." ;;

    *)
      warn "no MAC layer present (typical on Arch). Strongly consider installing"
      warn "AppArmor (pacman -S apparmor) or SELinux; egress rules (3c) are your"
      warn "main containment until then." ;;
  esac
}

#------------------------------------------------------------------------------
# 3e. KERNEL / SYSCTL  -- same keys on every family; ICMP echo left ON
#------------------------------------------------------------------------------
harden_sysctl() {
  hdr "3e. KERNEL / SYSCTL"
  local f=/etc/sysctl.d/99-hardening.conf
  backup_file "$f"
  if [[ "$APPLY" -eq 1 ]]; then
    cat > "$f" <<'EOF'
# spoofing / routing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
# SYN flood resilience
net.ipv4.tcp_syncookies = 1
# ICMP: keep echo REPLY on (don't set icmp_echo_ignore_all); drop broadcast storms
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# exploit mitigations
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF
    sysctl --system >>"$LOG" 2>&1 && ok "sysctl applied (ICMP echo preserved)"
  else
    log "  [dry-run] would write $f (rp_filter, syncookies, ASLR, ptrace_scope; ICMP echo kept)"
  fi
}

#------------------------------------------------------------------------------
# 3f. WEB / PHP / DB  -- find php.ini dynamically; service names differ by family
#------------------------------------------------------------------------------
harden_web_db() {
  hdr "3f. WEB / PHP / DB"
  # Collect every php.ini in play (CLI, Apache SAPI, FPM) across all layouts.
  local inis=()
  command -v php >/dev/null 2>&1 && \
    while read -r i; do [[ -f "$i" ]] && inis+=("$i"); done \
      < <(php --ini 2>/dev/null | awk -F': *' '/(Loaded Configuration|Scan for additional)/{print $2}' | tr ',' '\n')
  # Debian stores them under /etc/php/<ver>/<sapi>/php.ini; sweep those too.
  while read -r i; do inis+=("$i"); done \
    < <(find /etc/php /etc/php.ini /etc/php*/ -name php.ini 2>/dev/null)
  # De-dup.
  mapfile -t inis < <(printf '%s\n' "${inis[@]}" | sort -u | grep -v '^$')

  if [[ "${#inis[@]}" -eq 0 ]]; then
    warn "no php.ini found -- app may not be PHP, skipping PHP hardening"
  else
    for phpini in "${inis[@]}"; do
      backup_file "$phpini"
      if [[ "$APPLY" -eq 1 ]]; then
        # Disable the exec family webshells depend on. If the real app needs one,
        # it'll break -- test the scored page and drop that function from the list.
        sed -i 's/^disable_functions *=.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,show_source/' "$phpini" 2>/dev/null \
          || echo 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen' >> "$phpini"
        sed -i 's/^expose_php *=.*/expose_php = Off/'            "$phpini"
        sed -i 's/^;* *allow_url_fopen *=.*/allow_url_fopen = Off/'   "$phpini"
        sed -i 's/^;* *allow_url_include *=.*/allow_url_include = Off/' "$phpini"
        ok "hardened $phpini"
      else
        log "  [dry-run] would disable PHP exec/url-include in $phpini"
      fi
    done
    warn "TEST the scored web page now -- if it broke, re-enable the one function it needs."
  fi

  # Hide the web-server version banner. Apache conf dir differs by family.
  local apconf=""
  [[ -d /etc/httpd/conf.d ]]    && apconf=/etc/httpd/conf.d/00-sec.conf        # RHEL/Arch
  [[ -d /etc/apache2/conf-available ]] && apconf=/etc/apache2/conf-available/00-sec.conf  # Debian
  if [[ -n "$apconf" ]]; then
    run_change "set ServerTokens Prod / ServerSignature Off" bash -c \
      "printf 'ServerTokens Prod\nServerSignature Off\nTraceEnable Off\n' > '$apconf'"
    # Debian needs the conf explicitly enabled.
    [[ "$FAMILY" == "debian" && "$APPLY" -eq 1 ]] && a2enconf 00-sec >>"$LOG" 2>&1
  fi

  # Restart whichever web service is actually running.
  if [[ "$APPLY" -eq 1 ]]; then
    for svc in $WEB_SVCS; do
      systemctl is-active "$svc" >/dev/null 2>&1 && run_change "restart $svc" systemctl restart "$svc"
    done
  fi

  log "\n  -- DB listeners (should be 127.0.0.1 unless remote access is required):"
  ss -tlnp | grep -E ':(3306|5432|1433) ' | sed 's/^/    /' | tee -a "$LOG" \
    || ok "no DB port listening externally"
}

#------------------------------------------------------------------------------
# 3g. LOGGING / TIME  -- auditd is cross-distro; time daemon name varies
#------------------------------------------------------------------------------
harden_logging() {
  hdr "3g. LOGGING / TIME"
  # auditd + a syslog daemon + a time daemon. Service names vary, so probe.
  run_change "ensure auditd present" bash -c "command -v auditctl >/dev/null || $PM_INSTALL audit auditd 2>/dev/null || true"
  for svc in auditd rsyslog systemd-journald; do
    systemctl is-active "$svc" >/dev/null 2>&1 && ok "$svc running" \
      || run_change "enable+start $svc" systemctl enable --now "$svc"
  done
  # Time sync: chronyd (RHEL/Arch), chrony (Debian service), or systemd-timesyncd.
  for tsvc in chronyd chrony systemd-timesyncd; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${tsvc}"; then
      run_change "enable+start $tsvc (time sync)" systemctl enable --now "$tsvc"; break
    fi
  done

  # Audit watches on exactly the persistence spots the hunt covers.
  local arules=/etc/audit/rules.d/99-hardening.rules
  if [[ "$APPLY" -eq 1 ]] && [[ -d /etc/audit/rules.d ]]; then
    backup_file "$arules"
    cat > "$arules" <<'EOF'
-w /etc/passwd -p wa -k ident
-w /etc/shadow -p wa -k ident
-w /etc/sudoers -p wa -k priv
-w /etc/sudoers.d/ -p wa -k priv
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /root/.ssh/ -p wa -k ssh_keys
-w /etc/ssh/ -p wa -k sshd
-w /etc/systemd/system/ -p wa -k units
-w /etc/ld.so.preload -p wa -k rootkit
EOF
    augenrules --load >>"$LOG" 2>&1 && ok "audit watch-rules loaded"
  else
    log "  [dry-run] would load audit watches on passwd/sudoers/cron/ssh/systemd"
  fi
}

#------------------------------------------------------------------------------
# 4. WATCH -- systemd-timer tripwire; re-diffs persistence spots every 5 min
#------------------------------------------------------------------------------
install_watcher() {
  hdr "4. TRIPWIRE / WATCHER"
  local script=/usr/local/sbin/harden-watch.sh
  if [[ "$APPLY" -eq 1 ]]; then
    mkdir -p /var/lib/harden-watch
    cat > "$script" <<'EOF'
#!/usr/bin/env bash
# harden-watch: snapshot persistence state, log anything that changed to syslog.
set -u
S=/var/lib/harden-watch; mkdir -p "$S"
snap() {                                  # snap <name> <command...>
  local n="$1"; shift
  "$@" > "$S/$n.new" 2>/dev/null
  if [[ -f "$S/$n.cur" ]] && ! diff -q "$S/$n.cur" "$S/$n.new" >/dev/null; then
    logger -t harden-watch "CHANGE in $n:"
    diff "$S/$n.cur" "$S/$n.new" | logger -t harden-watch
  fi
  mv "$S/$n.new" "$S/$n.cur"
}
snap passwd    getent passwd
snap listeners ss -tulpnH
snap authkeys  bash -c 'for h in /root /home/*; do cat "$h/.ssh/authorized_keys" 2>/dev/null; done'
snap crontabs  bash -c 'for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null; done'
snap units     bash -c 'ls -l /etc/systemd/system/*.service 2>/dev/null'
snap suid      bash -c 'find / -xdev -perm -4000 -type f 2>/dev/null'
EOF
    chmod 700 "$script"
    cat > /etc/systemd/system/harden-watch.service <<EOF
[Unit]
Description=persistence watcher
[Service]
Type=oneshot
ExecStart=$script
EOF
    cat > /etc/systemd/system/harden-watch.timer <<'EOF'
[Unit]
Description=run persistence watcher every 5 min
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now harden-watch.timer >>"$LOG" 2>&1
    ok "watcher installed; changes land in syslog tagged 'harden-watch'"
    log "     journalctl -t harden-watch -f    # or: grep harden-watch /var/log/syslog"
  else
    log "  [dry-run] would install $script + harden-watch.timer (5-min persistence diff)"
  fi
}

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
detect_platform
inventory
hunt
if [[ "$HUNT_ONLY" -eq 1 ]]; then
  hdr "DONE (hunt-only)"; log "review red items; re-run with --apply to harden."; exit 0
fi

harden_ssh
harden_accounts
harden_firewall
harden_mac
harden_sysctl
harden_web_db
harden_logging
install_watcher

hdr "SUMMARY"
log "family: $FAMILY   firewall: $FW   MAC: $MAC"
log "mode  : $([[ $APPLY -eq 1 ]] && echo 'APPLIED' || echo 'DRY-RUN (no changes)')"
log "artifacts: $WORKDIR  (baseline/ backup/ run.log)"
[[ "$APPLY" -eq 0 ]] && log "\n>> DRY RUN. Re-run with --apply (and --ssh-key) to make changes."
log "\nGuardrails respected: ICMP echo left UP; inbound services open to all sources;"
log "egress is where we clamp. Password rotation for scored users is done out-of-band."
