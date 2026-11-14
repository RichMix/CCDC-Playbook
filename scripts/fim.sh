#!/usr/bin/env bash
#===============================================================================
# fim.sh  --  file-integrity monitor: alert on any change outside the whitelist
#-------------------------------------------------------------------------------
# Keeps a baseline of sha256 hashes for the paths that matter (the "known-good
# whitelist") and, on every check, reports anything that was ADDED, CHANGED, or
# REMOVED versus that baseline -- except paths matched by the ignore-list, which
# are expected to churn (logs, caches, runtime files).
#
# This is the heavier sibling of harden-watch (in harden-linux.sh): harden-watch
# diffs a few persistence spots every 5 min; fim.sh fingerprints whole trees and
# can run as a systemd timer with syslog alerting. Dependency-free (coreutils +
# systemd); for a full-featured alternative see AIDE (noted at the bottom).
#
# WORKFLOW:
#   1. Harden the box FIRST, then capture the baseline once it's in a known-good
#      state:                       sudo ./fim.sh --baseline
#   2. Check for drift any time:    sudo ./fim.sh --check
#   3. Run it continuously:         sudo ./fim.sh --install   (systemd timer, 5 min)
#      ...then watch alerts:        journalctl -t ccdc-fim -f
#   4. After an APPROVED change (you patched a pkg, edited a conf on purpose),
#      re-bless the baseline:       sudo ./fim.sh --accept     (or --baseline)
#
# CONFIG (override on the command line):
#   --paths  "<space-separated dirs/files to watch>"
#   --ignore "<space-separated glob patterns to NOT alert on>"
#   --store  <dir for baseline + state>   (default /var/lib/ccdc-fim)
#   --interval <minutes>                  (--install timer period, default 5)
#===============================================================================

set -uo pipefail

#------------------------------------------------------------------------------
# Defaults -- tuned for CCDC hosts. Watch the spots an intruder tampers with;
# ignore the spots the OS legitimately rewrites.
#------------------------------------------------------------------------------
# WHAT TO WATCH: binaries, config, web content, auth/persistence surfaces.
PATHS="/etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
/boot/grub2 /var/www /srv/http /srv/www /root/.ssh \
/etc/systemd/system /etc/cron.d /etc/cron.daily /etc/cron.hourly"

# WHAT TO IGNORE (the whitelist of expected churn): these change on their own,
# so a diff here is noise, not an intrusion. Shell globs, matched per path.
IGNORE="/etc/mtab /etc/adjtime /etc/resolv.conf /etc/machine-id \
/etc/ld.so.cache /etc/*.cache /var/log/* /var/cache/* *.swp *.tmp *~ \
/etc/sysconfig/network-scripts/ifcfg-* /etc/.updated /etc/.pwd.lock"

STORE="/var/lib/ccdc-fim"      # baseline + state live here
INTERVAL=5                      # --install timer period (minutes)
ACTION=""                       # baseline | check | accept | install | uninstall

while [[ $# -gt 0 ]]; do
  case "$1" in
    --baseline)  ACTION="baseline" ;;
    --check)     ACTION="check" ;;
    --accept)    ACTION="accept" ;;        # re-bless current state as good
    --install)   ACTION="install" ;;
    --uninstall) ACTION="uninstall" ;;
    --paths)     PATHS="${2:-}"; shift ;;
    --ignore)    IGNORE="${2:-}"; shift ;;
    --store)     STORE="${2:-}"; shift ;;
    --interval)  INTERVAL="${2:-}"; shift ;;
    -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

[[ "$(id -u)" -eq 0 ]] || { echo "[!] run as root (sudo)." >&2; exit 1; }
[[ -n "$ACTION" ]] || { echo "[!] pick one: --baseline | --check | --accept | --install | --uninstall"; exit 2; }

mkdir -p "$STORE"
BASELINE="${STORE}/baseline.sha256"      # the approved manifest (the whitelist)
IGNORE_FILE="${STORE}/ignore.list"       # saved so the timer uses the same set
SELF="$(readlink -f "$0")"               # absolute path for the systemd unit

#------------------------------------------------------------------------------
# build_manifest : hash every watched file, skipping ignore-list matches.
# Output is "<sha256>  <path>" sorted by path, ready to diff.
#------------------------------------------------------------------------------
build_manifest() {
  # Turn the IGNORE globs into find -path ... -prune predicates so we never even
  # descend into churny trees (fast, and avoids false positives).
  local prune=() first=1
  for g in $IGNORE; do
    if [[ $first -eq 1 ]]; then prune+=( -path "$g" ); first=0
    else prune+=( -o -path "$g" ); fi
  done

  # For each existing watch root, find regular files, prune ignores, hash them.
  for root in $PATHS; do
    [[ -e "$root" ]] || continue
    if [[ ${#prune[@]} -gt 0 ]]; then
      find "$root" -xdev \( "${prune[@]}" \) -prune -o -type f -print0 2>/dev/null
    else
      find "$root" -xdev -type f -print0 2>/dev/null
    fi
  done | sort -z | xargs -0 -r sha256sum 2>/dev/null | sort -k2
}

#------------------------------------------------------------------------------
# Actions
#------------------------------------------------------------------------------
case "$ACTION" in

  baseline|accept)
    # Capture the current (known-good) state as the approved whitelist.
    echo "$IGNORE" > "$IGNORE_FILE"
    build_manifest > "$BASELINE"
    # Protect the baseline: root-only, and record its own hash so tampering with
    # the baseline itself is detectable.
    chmod 600 "$BASELINE"
    sha256sum "$BASELINE" > "${BASELINE}.self"
    n=$(wc -l < "$BASELINE")
    echo "[+] baseline ${ACTION}: $n files fingerprinted -> $BASELINE"
    [[ "$ACTION" == "accept" ]] && echo "    (current state re-blessed as known-good)" ;;

  check)
    if [[ ! -f "$BASELINE" ]]; then
      echo "[!] no baseline yet -- run: sudo $0 --baseline"; exit 3
    fi
    # First, has the baseline itself been tampered with?
    if ! sha256sum -c "${BASELINE}.self" >/dev/null 2>&1; then
      echo "[XX] BASELINE FILE ITSELF CHANGED -- possible tampering with $BASELINE"
    fi
    # Load the same ignore set the baseline was built with, for an apples-to-apples diff.
    [[ -f "$IGNORE_FILE" ]] && IGNORE="$(cat "$IGNORE_FILE")"

    now="$(mktemp)"
    build_manifest > "$now"

    # Normalize both manifests to "<path>\t<hash>" sorted by path. sha256sum
    # output is a fixed 64-hex hash + two spaces + the path, so we split on
    # character position -- that keeps paths containing spaces intact (awk $2
    # would truncate them).
    norm() { sed -E 's/^([0-9a-f]{64})  (.*)$/\2\t\1/' | LC_ALL=C sort -t "$(printf '\t')" -k1,1; }
    norm < "$BASELINE" > "${now}.b"
    norm < "$now"      > "${now}.n"

    TAB="$(printf '\t')"
    # CHANGED = path present in both, hash differs. join on the path field.
    join -t "$TAB" -j1 "${now}.b" "${now}.n" 2>/dev/null \
      | awk -F"$TAB" '$2 != $3 {print "  [CHANGED] "$1}' > "${now}.mod"
    # ADDED = path only in current; REMOVED = path only in baseline.
    comm -13 <(cut -f1 "${now}.b") <(cut -f1 "${now}.n") | sed 's/^/  [ADDED]   /' > "${now}.add"
    comm -23 <(cut -f1 "${now}.b") <(cut -f1 "${now}.n") | sed 's/^/  [REMOVED] /' > "${now}.del"

    total=$(( $(wc -l < "${now}.mod") + $(wc -l < "${now}.add") + $(wc -l < "${now}.del") ))
    if [[ "$total" -eq 0 ]]; then
      echo "[ok] no drift -- all watched files match the baseline."
    else
      echo "[XX] $total change(s) OUTSIDE the whitelist:"
      cat "${now}.mod" "${now}.add" "${now}.del"
      # Also emit to syslog so the timer/SIEM sees it even when run unattended.
      { echo "FIM DRIFT: $total change(s) outside whitelist"
        cat "${now}.mod" "${now}.add" "${now}.del"; } | logger -t ccdc-fim
    fi
    rm -f "$now" "${now}".{mod,add,del,b,n}
    [[ "$total" -eq 0 ]] && exit 0 || exit 1 ;;   # non-zero exit = drift (for alerting)

  install)
    # Persist the config, then a systemd service+timer that runs --check.
    echo "$IGNORE" > "$IGNORE_FILE"
    [[ -f "$BASELINE" ]] || { echo "[*] no baseline yet -- creating one now"; "$SELF" --baseline; }
    cat > /etc/systemd/system/ccdc-fim.service <<EOF
[Unit]
Description=CCDC file-integrity check (alert on drift outside whitelist)
[Service]
Type=oneshot
# --store pins the same baseline; exit code 1 on drift shows in 'systemctl status'.
ExecStart=${SELF} --check --store ${STORE}
EOF
    cat > /etc/systemd/system/ccdc-fim.timer <<EOF
[Unit]
Description=Run CCDC file-integrity check every ${INTERVAL} min
[Timer]
OnBootSec=3min
OnUnitActiveSec=${INTERVAL}min
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now ccdc-fim.timer
    echo "[+] FIM timer installed (every ${INTERVAL} min). Alerts -> journalctl -t ccdc-fim -f" ;;

  uninstall)
    systemctl disable --now ccdc-fim.timer 2>/dev/null
    rm -f /etc/systemd/system/ccdc-fim.service /etc/systemd/system/ccdc-fim.timer
    systemctl daemon-reload
    echo "[*] FIM timer removed (baseline in $STORE kept; delete it manually if you want)" ;;
esac

# NOTE: for a hardened, policy-rich FIM, AIDE (aide.conf + `aide --init/--check`)
# is the established tool -- install it when you have time. This script is the
# zero-dependency version you can drop on any box mid-competition.
