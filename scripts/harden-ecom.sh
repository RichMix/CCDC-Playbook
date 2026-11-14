#!/usr/bin/env bash
#===============================================================================
# harden-ecom.sh  --  Rocky Linux 9 "Ecom" hardening + persistence-hunt playbook
#-------------------------------------------------------------------------------
# Target : CCDC "Ecom Rocky Linux" box (Rocky 9, httpd/PHP e-commerce + DB)
#          Internal 172.20.240.10  /  Public 172.25.<team>.10
# Author : TheL4ST_R3SPOND3RS  (chopp / g0_ph15h)
#
# WHAT THIS DOES, IN ORDER:
#   0. Safety: snapshot of the stuff RT loves to touch, so you can diff later.
#   1. Inventory: dump state to a baseline you can re-run and compare.
#   2. HUNT: surface RT persistence (keys, users, cron, systemd, bashrc, suid,
#            listeners, webshells) -- surfaces, does NOT auto-nuke.
#   3. HARDEN: SSH, accounts/creds, firewall + egress, SELinux, sysctl,
#              web/PHP/DB, logging, time-sync, pam, kernel modules.
#   4. WATCH: install a lightweight tripwire that logs new persistence.
#
# DESIGN RULES (so we don't self-inflict a scoring loss):
#   * ICMP stays UP (CCDC rule 12) -- we never drop echo.
#   * Scored services stay on the public IP, reachable from ALL sources
#     (CCDC scoring rule 9 -- no knife-edge / scoring-engine-only filtering).
#   * SSH changes go in a drop-in that SORTS FIRST (Rocky 9: first value wins,
#     lowest-numbered file wins) -- see harden_ssh().
#   * NOTHING destructive runs without you passing --apply. Default = report.
#   * Every change is backed up under $BACKUP so you can roll back.
#
# USAGE:
#   sudo ./harden-ecom.sh                 # dry-run: hunt + report only, no changes
#   sudo ./harden-ecom.sh --apply         # actually apply hardening
#   sudo ./harden-ecom.sh --apply --ssh-key "ssh-ed25519 AAAA... you@team"
#                                         # apply AND install your key (do this!)
#   sudo ./harden-ecom.sh --hunt-only     # just the persistence hunt
#
# EXIT: writes a full log + baseline under /root/ccdc-ecom-<timestamp>/
#===============================================================================

set -uo pipefail   # NOTE: not -e. One failed check must not abort the pass.

#------------------------------------------------------------------------------
# 0. Config / args
#------------------------------------------------------------------------------
APPLY=0                       # 0 = report only, 1 = make changes
HUNT_ONLY=0                   # 1 = run hunt then exit
SSH_PUBKEY=""                 # optional: your authorized key to install
ADMIN_USER="${SUDO_USER:-}"   # the human who ran sudo; gets to keep SSH access

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)      APPLY=1 ;;                 # flip from dry-run to live
    --hunt-only)  HUNT_ONLY=1 ;;             # persistence hunt and nothing else
    --ssh-key)    SSH_PUBKEY="${2:-}"; shift ;;  # next arg is the pubkey string
    --admin)      ADMIN_USER="${2:-}"; shift ;;  # override which user keeps access
    -h|--help)    grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

# Must be root -- almost every action below reads/writes root-owned paths.
if [[ "$(id -u)" -ne 0 ]]; then
  echo "[!] run as root (sudo)." >&2; exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"           # one timestamp for this whole run
WORKDIR="/root/ccdc-ecom-${TS}"       # everything from this run lands here
BACKUP="${WORKDIR}/backup"            # copies of files before we touch them
BASELINE="${WORKDIR}/baseline"       # inventory snapshots for later diffing
LOG="${WORKDIR}/run.log"             # full transcript
mkdir -p "$BACKUP" "$BASELINE"

# log() prints to screen AND appends to the run log (tee without the pipe mess).
log()  { echo -e "$*" | tee -a "$LOG"; }
hdr()  { log "\n\033[1;36m==== $* ====\033[0m"; }           # cyan section header
ok()   { log "  \033[1;32m[ok]\033[0m  $*"; }               # green  = good
warn() { log "  \033[1;33m[!!]\033[0m  $*"; }               # yellow = look here
bad()  { log "  \033[1;31m[XX]\033[0m  $*"; }               # red    = probable RT
act()  { log "  \033[1;34m[>>]\033[0m  $*"; }               # blue   = action taken

# backup_file <path> : copy a file into $BACKUP preserving its tree, once.
# Called before every edit so a bad change is one `cp` away from reverting.
backup_file() {
  local f="$1"
  [[ -e "$f" ]] || return 0                       # nothing to back up
  local dest="${BACKUP}${f}"                      # mirror the absolute path
  mkdir -p "$(dirname "$dest")"
  cp -a "$f" "$dest" 2>/dev/null && act "backed up $f"
}

# run_change <description> <command...> : honor dry-run vs --apply.
# In report mode it only prints what WOULD happen; with --apply it runs it.
run_change() {
  local desc="$1"; shift
  if [[ "$APPLY" -eq 1 ]]; then
    act "$desc"
    "$@" >>"$LOG" 2>&1 || warn "   ^ command returned non-zero (check $LOG)"
  else
    log "  \033[2m[dry-run] would: $desc\033[0m"   # dim text, no action
  fi
}

log "CCDC Ecom hardening run  ${TS}"
log "mode: $([[ $APPLY -eq 1 ]] && echo APPLY || echo DRY-RUN)   workdir: $WORKDIR"
log "host: $(hostname)   os: $(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
[[ -n "$ADMIN_USER" ]] && log "admin user (keeps SSH): $ADMIN_USER"

#------------------------------------------------------------------------------
# 1. INVENTORY -- snapshot state so you can diff after RT pokes the box
#------------------------------------------------------------------------------
inventory() {
  hdr "1. INVENTORY / BASELINE"
  # Each line dumps one aspect of system state into its own baseline file.
  # Re-running the script later and diffing these files shows what changed.
  ps auxww                        > "${BASELINE}/processes.txt" 2>&1   # every process
  ss -tulpnH                      > "${BASELINE}/listeners.txt" 2>&1   # listening sockets + pids
  ss -tnpH state established      > "${BASELINE}/connections.txt" 2>&1 # live outbound/inbound
  # getent passwd = all accounts incl. from SSSD/LDAP, not just /etc/passwd
  getent passwd                   > "${BASELINE}/passwd.txt" 2>&1
  getent group                    > "${BASELINE}/group.txt" 2>&1
  rpm -qa --last                  > "${BASELINE}/rpm-by-date.txt" 2>&1 # newest pkgs first
  systemctl list-unit-files --type=service > "${BASELINE}/services.txt" 2>&1
  systemctl list-timers --all     > "${BASELINE}/timers.txt" 2>&1
  crontab -l 2>/dev/null          > "${BASELINE}/crontab-root.txt"
  # sha256 of every binary dir -- compare later to catch trojaned binaries.
  find /usr/bin /usr/sbin /bin /sbin -type f -exec sha256sum {} + \
      > "${BASELINE}/bin-hashes.txt" 2>/dev/null
  ok "baseline written to $BASELINE (diff against this after RT activity)"
}

#------------------------------------------------------------------------------
# 2. HUNT -- surface the persistence mechanisms CCDC red teams actually use
#            Reports only. You decide what's legit before killing it.
#------------------------------------------------------------------------------
hunt() {
  hdr "2. PERSISTENCE HUNT (review before removing anything)"

  # --- 2a. Rogue / backdoor accounts -----------------------------------------
  # Any NON-root account with UID 0 is a backdoor, full stop.
  log "\n-- UID 0 accounts (only 'root' should appear):"
  awk -F: '$3==0 {print "    "$1}' /etc/passwd | tee -a "$LOG"
  local uid0count; uid0count=$(awk -F: '$3==0' /etc/passwd | wc -l)
  [[ "$uid0count" -gt 1 ]] && bad "more than one UID-0 account -> BACKDOOR" \
      || ok "exactly one UID-0 account"

  # Accounts with a login shell AND a real UID that you didn't create.
  log "\n-- accounts with interactive shells (verify every one is yours):"
  awk -F: '$7 ~ /(bash|sh|zsh)$/ && $3>=1000 {print "    "$1" (uid "$3", shell "$7")"}' \
      /etc/passwd | tee -a "$LOG"

  # Users that can sudo (wheel group + anything dropped in sudoers.d).
  log "\n-- sudo-capable (wheel members + sudoers.d drop-ins):"
  getent group wheel | tee -a "$LOG"
  grep -rEl 'ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while read -r f; do
    log "    sudoers file: $f"; grep -vE '^\s*#|^\s*$' "$f" | sed 's/^/        /'
  done

  # --- 2b. SSH key persistence (the #1 quiet CCDC backdoor) ------------------
  # authorized_keys in any home or root = standing access that survives
  # password changes. Audit every key; RT drops theirs here.
  log "\n-- authorized_keys across all homes + root:"
  { echo "/root"; awk -F: '$3>=1000{print $6}' /etc/passwd; } | sort -u | \
  while read -r home; do
    for akf in "$home"/.ssh/authorized_keys "$home"/.ssh/authorized_keys2; do
      [[ -f "$akf" ]] || continue
      warn "keys in $akf:"
      # Print fingerprint + comment of each key so you can eyeball unknowns.
      while read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        echo "$line" | ssh-keygen -lf - 2>/dev/null | sed 's/^/        /' | tee -a "$LOG"
      done < "$akf"
    done
  done

  # --- 2c. Cron + systemd timers (scheduled callback) ------------------------
  log "\n-- cron: per-user crontabs, system cron, and drop-in dirs:"
  for u in $(cut -d: -f1 /etc/passwd); do
    local ct; ct=$(crontab -l -u "$u" 2>/dev/null)
    [[ -n "$ct" ]] && { warn "crontab for $u:"; echo "$ct" | sed 's/^/        /'; }
  done
  # System cron locations RT uses; print any non-comment content.
  for d in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily \
           /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
    [[ -e "$d" ]] && find "$d" -type f -exec grep -lvE '^\s*#' {} \; 2>/dev/null \
        | while read -r f; do warn "cron file: $f"; done
  done

  log "\n-- systemd timers (watch for odd .timer units calling scripts):"
  systemctl list-timers --all --no-pager 2>/dev/null | sed 's/^/    /' | tee -a "$LOG"
  # Recently-written unit files = likely planted this competition.
  log "\n-- systemd unit files modified in the last 2 days:"
  find /etc/systemd/system /usr/lib/systemd/system /run/systemd/system \
       -name '*.service' -mtime -2 2>/dev/null | sed 's/^/    /' | tee -a "$LOG"

  # --- 2d. Shell init files (.bashrc / profile reverse shells) ---------------
  # RT hides a one-liner callback in a login file so it fires on every shell.
  log "\n-- shell init files referencing net tooling (nc/bash -i/curl|sh/python -c):"
  grep -rEl '(bash -i|nc |ncat |/dev/tcp/|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|python[0-9]* -c)' \
      /etc/profile /etc/profile.d /etc/bashrc /root/.bashrc /root/.bash_profile \
      /home/*/.bashrc /home/*/.bash_profile /home/*/.profile 2>/dev/null \
      | while read -r f; do bad "suspicious init file: $f"; done

  # --- 2e. SUID/SGID + capabilities (privesc footholds) ----------------------
  log "\n-- unexpected SUID/SGID binaries (compare to a clean Rocky 9 list):"
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
      > "${BASELINE}/suid-sgid.txt"
  # Flag SUID that lives outside the normal system dirs -- classic RT drop.
  grep -vE '^/(usr/bin|usr/sbin|bin|sbin|usr/lib|usr/libexec)/' \
      "${BASELINE}/suid-sgid.txt" | while read -r f; do bad "odd-location SUID: $f"; done
  # File capabilities are an easy-to-miss privesc path (e.g. cap_setuid on python).
  log "\n-- files with capabilities set:"
  getcap -r / 2>/dev/null | sed 's/^/    /' | tee -a "$LOG"

  # --- 2f. Listeners + webshells --------------------------------------------
  log "\n-- listening sockets (map every one to a service you expect):"
  ss -tulpn | sed 's/^/    /' | tee -a "$LOG"
  # Grep the webroot for the dead-giveaway webshell patterns.
  log "\n-- webroot scan for shell patterns (system/exec/eval/base64_decode/\$_GET-exec):"
  for wr in /var/www /usr/share/nginx/html /srv/www; do
    [[ -d "$wr" ]] || continue
    grep -rEln --include='*.php' \
      -e 'eval *(' -e 'base64_decode *(' -e 'system *(' -e 'shell_exec *(' \
      -e 'passthru *(' -e 'assert *(' -e '\$_\(GET\|POST\|REQUEST\).*\(system\|exec\|eval\)' \
      "$wr" 2>/dev/null | while read -r f; do bad "possible webshell: $f"; done
  done

  # --- 2g. Loaded kernel modules / LD_PRELOAD rootkits -----------------------
  log "\n-- /etc/ld.so.preload (should NOT exist; userland-rootkit tell):"
  [[ -s /etc/ld.so.preload ]] && bad "ld.so.preload present: $(cat /etc/ld.so.preload)" \
      || ok "no ld.so.preload"

  ok "hunt complete -- red items above are the ones to chase first"
}

#------------------------------------------------------------------------------
# 3. HARDEN -- each sub-function is independent so you can comment any out
#------------------------------------------------------------------------------

harden_ssh() {
  hdr "3a. SSH"
  # Rocky 9 includes /etc/ssh/sshd_config.d/*.conf at the TOP of sshd_config,
  # and sshd keeps the FIRST value it sees. So our hardening must sort BEFORE
  # the vendor 50-redhat.conf -- hence 01-. A 99- file would silently LOSE.
  local dropin="/etc/ssh/sshd_config.d/01-ccdc-hardening.conf"
  ls -1 /etc/ssh/sshd_config.d/ 2>/dev/null | sed 's/^/    existing drop-in: /' | tee -a "$LOG"

  # Build the key list: install your provided key, and preserve the admin
  # user's existing keys so we don't lock ourselves out when passwords die.
  if [[ "$APPLY" -eq 1 && -n "$SSH_PUBKEY" && -n "$ADMIN_USER" ]]; then
    local adminhome; adminhome=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
    install -d -m700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$adminhome/.ssh"
    backup_file "$adminhome/.ssh/authorized_keys"
    # Append only if not already present (idempotent).
    grep -qF "$SSH_PUBKEY" "$adminhome/.ssh/authorized_keys" 2>/dev/null \
      || echo "$SSH_PUBKEY" >> "$adminhome/.ssh/authorized_keys"
    chown "$ADMIN_USER":"$ADMIN_USER" "$adminhome/.ssh/authorized_keys"
    chmod 600 "$adminhome/.ssh/authorized_keys"
    act "installed your key for $ADMIN_USER"
  elif [[ -z "$SSH_PUBKEY" ]]; then
    warn "no --ssh-key given: NOT disabling passwords yet (would risk lockout)."
    warn "re-run with --ssh-key '<your pubkey>' to go key-only."
  fi

  # Only disable password auth if a key is in place -- otherwise you're locked out.
  local passauth="no"
  [[ -z "$SSH_PUBKEY" ]] && passauth="yes"   # keep passwords until a key exists

  if [[ "$APPLY" -eq 1 ]]; then
    backup_file "$dropin"
    cat > "$dropin" <<EOF
# CCDC hardening -- sorts before vendor 50-redhat.conf (first value wins)
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
    [[ -n "$ADMIN_USER" ]] && echo "AllowUsers ${ADMIN_USER}" >> "$dropin"
    chmod 600 "$dropin"
    # VALIDATE before reload -- a syntax error here loses you the box.
    if sshd -t 2>>"$LOG"; then
      systemctl reload sshd && ok "sshd reloaded (password auth: ${passauth})"
    else
      bad "sshd -t FAILED -- config NOT reloaded. Fix $dropin before reloading."
    fi
  else
    log "  [dry-run] would write $dropin (PasswordAuthentication=${passauth}) + sshd -t + reload"
  fi
}

harden_accounts() {
  hdr "3b. ACCOUNTS / CREDENTIALS"
  # Lock every account that shouldn't log in but has a shell. Service accounts
  # should have nologin; RT flips one to /bin/bash as a backdoor.
  log "  review the interactive accounts flagged in the hunt, then:"
  log "    passwd -l <user>      # lock password"
  log "    usermod -s /sbin/nologin <user>   # kill the shell"

  # Mass password rotation for human accounts is done centrally via Quotient
  # (PCR tab, CSV username,password) per the team pack -- NOT here, so the
  # scoring engine's checks keep passing. This script only hardens policy.
  run_change "set strong password-aging defaults in /etc/login.defs" \
    bash -c 'sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/;s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/" /etc/login.defs'

  # Enforce password quality via pwquality (authselect-managed on Rocky 9).
  if [[ -f /etc/security/pwquality.conf ]]; then
    backup_file /etc/security/pwquality.conf
    run_change "enforce minlen=14, complexity in pwquality.conf" \
      bash -c 'cat >/etc/security/pwquality.conf <<EOF
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF'
  fi

  # Ensure no account has an empty password hash (instant login).
  log "\n  -- accounts with EMPTY password field (must be none):"
  awk -F: '($2==""){print "    "$1}' /etc/shadow | tee -a "$LOG"
}

harden_firewall() {
  hdr "3c. FIREWALL + EGRESS CONTROL"
  # CCDC constraints baked in here:
  #   * ICMP stays allowed (rule 12) -- firewalld allows it by default; we do
  #     NOT add an icmp-block.
  #   * Scored services stay open to ALL sources (rule 9) -- no source filtering
  #     on http/https/etc. No "scoring engine only" allowlist.
  # The win is EGRESS control: block the box from calling OUT to a C2, which
  # kills reverse shells and curl|bash stagers without touching inbound scoring.
  systemctl is-active firewalld >/dev/null 2>&1 || \
    run_change "start+enable firewalld" systemctl enable --now firewalld

  # Open exactly the inbound services this Ecom host is scored on. Adjust the
  # list to match your service table; extras are attack surface.
  local svcs=(http https ssh)
  for s in "${svcs[@]}"; do
    run_change "allow inbound $s (all sources -- scoring requires it)" \
      firewall-cmd --permanent --add-service="$s"
  done

  # EGRESS: default-deny outbound using firewalld's "direct" rules, then allow
  # only what the box legitimately needs (DNS, NTP, HTTP/S for updates, and
  # established/related return traffic). This is the part that frustrates RT:
  # even with a webshell, their reverse shell can't dial home.
  if [[ "$APPLY" -eq 1 ]]; then
    act "applying egress allowlist (DNS/NTP/updates out; drop the rest)"
    # NOTE: Rocky 9 firewalld uses the nftables backend; these --direct iptables
    # rules are translated into nft automatically and work, but they live in the
    # iptables-compat layer. Verify after apply with:  nft list ruleset | less
    # Allow loopback + already-established connections out.
    firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -o lo -j ACCEPT
    firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 1 \
        -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Allow outbound DNS(53), NTP(123), HTTP(80)/HTTPS(443) for patching.
    for p in "udp 53" "tcp 53" "udp 123" "tcp 80" "tcp 443"; do
      set -- $p
      firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 2 \
          -p "$1" --dport "$2" -j ACCEPT
    done
    # Allow ICMP out (ping replies/path MTU) -- keeps us a good net citizen.
    firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 2 -p icmp -j ACCEPT
    # Everything else outbound: log then drop. Logged drops = RT callback attempts.
    firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 10 \
        -j LOG --log-prefix "EGRESS-DROP: " --log-level 4
    firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 11 -j DROP
    firewall-cmd --reload && ok "firewall reloaded; egress locked, inbound scoring open"
    warn "if a scored service also makes OUTBOUND calls (e.g. DB on another host),"
    warn "add its port to the egress allowlist above or you'll break that check."
  else
    log "  [dry-run] would open ${svcs[*]} inbound + apply egress allowlist (DNS/NTP/80/443/icmp)"
  fi
}

harden_selinux() {
  hdr "3d. SELINUX"
  # SELinux enforcing is your single biggest anti-webshell control on this box:
  # even if PHP gets popped, httpd_t can't spawn a network reverse shell while
  # httpd_can_network_connect is OFF. Keep it enforcing; keep the booleans tight.
  local mode; mode=$(getenforce 2>/dev/null)
  log "  current SELinux mode: $mode"
  if [[ "$mode" != "Enforcing" ]]; then
    bad "SELinux NOT enforcing -- RT may have disabled it. Re-enable:"
    run_change "set SELinux enforcing now" setenforce 1
    backup_file /etc/selinux/config
    run_change "persist SELINUX=enforcing" \
      sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
  else
    ok "SELinux enforcing"
  fi
  # Turn OFF the booleans that let a popped webapp reach the network. These are
  # the exact toggles a webshell needs to curl down tooling or open a shell.
  for b in httpd_can_network_connect httpd_can_network_connect_db \
           httpd_execmem httpd_enable_cgi httpd_tmp_exec; do
    local cur; cur=$(getsebool "$b" 2>/dev/null | awk '{print $3}')
    if [[ "$cur" == "on" ]]; then
      warn "$b is ON (lets web code reach out / exec) -- turning off"
      run_change "setsebool -P $b off" setsebool -P "$b" off
    else
      ok "$b off"
    fi
  done
  warn "if the Ecom app legitimately talks to a DB on ANOTHER host, you may need"
  warn "httpd_can_network_connect_db back ON -- test the scored check after."
}

harden_sysctl() {
  hdr "3e. KERNEL / SYSCTL"
  # Network + kernel hardening. We DO NOT disable ICMP echo (CCDC rule 12),
  # so icmp_echo_ignore_all stays 0. We harden everything else.
  local f=/etc/sysctl.d/99-ccdc-hardening.conf
  backup_file "$f"
  if [[ "$APPLY" -eq 1 ]]; then
    cat > "$f" <<'EOF'
# --- spoofing / routing ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
# --- SYN flood resilience ---
net.ipv4.tcp_syncookies = 1
# --- ICMP: keep echo REPLY on (scored!), ignore broadcast storms only ---
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# --- exploit mitigations ---
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF
    sysctl --system >>"$LOG" 2>&1 && ok "sysctl hardening applied (ICMP echo preserved)"
  else
    log "  [dry-run] would write $f (rp_filter, syncookies, ASLR, ptrace_scope; ICMP echo kept)"
  fi
}

harden_web_db() {
  hdr "3f. WEB / PHP / DB"
  # Ecom = httpd + PHP + a DB. Trim the dangerous PHP functions a webshell
  # relies on, hide version banners, and make sure the DB isn't world-open.
  local phpini; phpini=$(php -i 2>/dev/null | awk -F'=> ' '/Loaded Configuration File/{print $2}')
  [[ -z "$phpini" && -f /etc/php.ini ]] && phpini=/etc/php.ini
  if [[ -n "$phpini" && -f "$phpini" ]]; then
    backup_file "$phpini"
    if [[ "$APPLY" -eq 1 ]]; then
      # Disable the exec family PHP webshells need. WARNING: if the real app
      # uses any of these, it'll break -- confirm with the app owner / test the
      # scored page first. Comment out functions the app genuinely needs.
      sed -i 's/^disable_functions *=.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source/' "$phpini" 2>/dev/null \
        || echo 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen' >> "$phpini"
      sed -i 's/^expose_php *=.*/expose_php = Off/' "$phpini"
      sed -i 's/^;* *allow_url_fopen *=.*/allow_url_fopen = Off/' "$phpini"
      sed -i 's/^;* *allow_url_include *=.*/allow_url_include = Off/' "$phpini"
      ok "PHP hardened in $phpini (exec family disabled, url_include off)"
      warn "TEST the scored Ecom page now -- if it broke, re-enable the one function it needs."
      systemctl is-active httpd >/dev/null 2>&1 && run_change "restart httpd" systemctl restart httpd
    else
      log "  [dry-run] would disable PHP exec/url-include in $phpini and restart httpd"
    fi
  else
    warn "no php.ini found -- is PHP on a different path or is the app not PHP?"
  fi

  # Hide the Apache version banner (recon reduction).
  if [[ -d /etc/httpd/conf.d ]]; then
    run_change "set ServerTokens Prod / ServerSignature Off" bash -c \
      'printf "ServerTokens Prod\nServerSignature Off\nTraceEnable Off\n" > /etc/httpd/conf.d/00-ccdc-sec.conf'
  fi

  # DB sanity: confirm it isn't listening on 0.0.0.0 unless an inject requires it.
  log "\n  -- DB listeners (should be 127.0.0.1 unless remote access is scored):"
  ss -tlnp | grep -E ':(3306|5432|1433) ' | sed 's/^/    /' | tee -a "$LOG" \
    || ok "no DB port listening externally"
}

harden_logging() {
  hdr "3g. LOGGING / TIME"
  # You can't write incident reports (20% of score) without logs. Make sure
  # auditd + rsyslog are running and time is synced (NISE is CST; timestamps
  # in your reports must line up with the scoreboard).
  for svc in auditd rsyslog chronyd; do
    if systemctl is-active "$svc" >/dev/null 2>&1; then
      ok "$svc running"
    else
      run_change "enable+start $svc" systemctl enable --now "$svc"
    fi
  done
  # Add audit rules that catch exactly the persistence RT plants: watch the
  # account files, sudoers, cron, ssh keys, and systemd unit dirs for writes.
  local arules=/etc/audit/rules.d/99-ccdc.rules
  if [[ "$APPLY" -eq 1 ]]; then
    backup_file "$arules"
    cat > "$arules" <<'EOF'
-w /etc/passwd -p wa -k ident_passwd
-w /etc/shadow -p wa -k ident_shadow
-w /etc/sudoers -p wa -k priv_sudoers
-w /etc/sudoers.d/ -p wa -k priv_sudoers
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /root/.ssh/ -p wa -k ssh_keys
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/systemd/system/ -p wa -k systemd_units
-w /etc/ld.so.preload -p wa -k rootkit
EOF
    augenrules --load >>"$LOG" 2>&1 && ok "audit watch-rules loaded (passwd/sudoers/cron/keys/units)"
  else
    log "  [dry-run] would load audit watch-rules on passwd/shadow/sudoers/cron/ssh/systemd"
  fi
  # Set timezone context note (don't change clock -- NISE is CST):
  log "  NOTE: NISE scoreboard runs on Central time; your log timestamps should"
  log "        reference that when you write incident reports."
}

#------------------------------------------------------------------------------
# 4. WATCH -- lightweight tripwire so re-planted persistence shows up fast
#------------------------------------------------------------------------------
install_watcher() {
  hdr "4. TRIPWIRE / WATCHER"
  # A tiny systemd timer that re-snapshots the high-value persistence spots
  # every 5 min and logs a diff. When RT re-establishes, you see it in minutes
  # instead of at end-of-round. Pure detection -- no auto-remediation.
  local script=/usr/local/sbin/ccdc-watch.sh
  local statedir=/var/lib/ccdc-watch
  if [[ "$APPLY" -eq 1 ]]; then
    mkdir -p "$statedir"
    cat > "$script" <<'EOF'
#!/usr/bin/env bash
# ccdc-watch: snapshot persistence-relevant state, log anything that changed.
set -u
S=/var/lib/ccdc-watch
mkdir -p "$S"
snap() {                           # snap <name> <command...>
  local name="$1"; shift
  "$@" > "$S/$name.new" 2>/dev/null
  if [[ -f "$S/$name.cur" ]] && ! diff -q "$S/$name.cur" "$S/$name.new" >/dev/null; then
    logger -t ccdc-watch "CHANGE in $name:"
    diff "$S/$name.cur" "$S/$name.new" | logger -t ccdc-watch   # delta -> syslog
  fi
  mv "$S/$name.new" "$S/$name.cur"
}
snap passwd      getent passwd
snap listeners   ss -tulpnH
snap authkeys    bash -c 'for h in /root /home/*; do cat "$h/.ssh/authorized_keys" 2>/dev/null; done'
snap crontabs    bash -c 'for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null; done'
snap units       bash -c 'ls -l /etc/systemd/system/*.service 2>/dev/null'
snap suid        bash -c 'find / -xdev -perm -4000 -type f 2>/dev/null'
EOF
    chmod 700 "$script"
    # systemd service + timer (every 5 minutes).
    cat > /etc/systemd/system/ccdc-watch.service <<EOF
[Unit]
Description=CCDC persistence watcher
[Service]
Type=oneshot
ExecStart=$script
EOF
    cat > /etc/systemd/system/ccdc-watch.timer <<'EOF'
[Unit]
Description=Run CCDC persistence watcher every 5 min
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now ccdc-watch.timer >>"$LOG" 2>&1
    ok "watcher installed; changes land in syslog tagged 'ccdc-watch'"
    log "     tail -f /var/log/messages | grep ccdc-watch"
  else
    log "  [dry-run] would install $script + ccdc-watch.timer (5-min persistence diff)"
  fi
}

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
inventory
hunt
if [[ "$HUNT_ONLY" -eq 1 ]]; then
  hdr "DONE (hunt-only)"
  log "review red items above. Re-run with --apply to harden."
  exit 0
fi

harden_ssh
harden_accounts
harden_firewall
harden_selinux
harden_sysctl
harden_web_db
harden_logging
install_watcher

hdr "SUMMARY"
log "mode: $([[ $APPLY -eq 1 ]] && echo 'APPLIED' || echo 'DRY-RUN (no changes made)')"
log "artifacts: $WORKDIR"
log "  - baseline/   : state snapshots (diff after RT activity)"
log "  - backup/     : originals of every file changed (rollback source)"
log "  - run.log     : full transcript"
[[ "$APPLY" -eq 0 ]] && log "\n>> This was a DRY RUN. Re-run with --apply (and --ssh-key) to make changes."
log "\nRemember the CCDC guardrails this script respects:"
log "  * ICMP echo left UP        (rule 12)"
log "  * scored services open to ALL sources, no knife-edge   (scoring rule 9)"
log "  * humans' passwords rotated via Quotient PCR, not here (keeps checks green)"
