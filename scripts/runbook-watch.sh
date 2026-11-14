#!/usr/bin/env bash
# Read-only, local watch snapshot for the Linux host runbooks.
set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
Usage: sudo bash scripts/runbook-watch.sh ROLE [--output-dir DIR] [--baseline FILE]
ROLE: ecom | email | splunk | workstation

Collects local read-only signals, writes a private TSV snapshot, and optionally
prints a diff against a snapshot from the same host and role. No fixes, scans,
network requests, service restarts, or scheduled jobs are performed.
EOF
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
role=${1:-}
case "$role" in ecom|email|splunk|workstation) ;; *) usage >&2; exit 2 ;; esac
shift

output_dir=/root/ccdc-watch
baseline=
while (($#)); do
  case "$1" in
    --output-dir|--baseline)
      (($# >= 2)) || { usage >&2; exit 2; }
      case "$1" in --output-dir) output_dir=$2 ;; --baseline) baseline=$2 ;; esac
      shift 2 ;;
    *) usage >&2; exit 2 ;;
  esac
done

if (( EUID != 0 )); then
  printf 'Run as root for a complete local snapshot.\n' >&2
  exit 3
fi
if [[ -n $baseline && ! -f $baseline ]]; then
  printf 'Baseline is not a regular file: %s\n' "$baseline" >&2
  exit 2
fi

if [[ $(realpath -m -- "$output_dir") != /root/* ]]; then
  printf 'Output directory must be under /root.\n' >&2
  exit 2
fi
mkdir -p -- "$output_dir"
if [[ -L $output_dir || $(realpath -- "$output_dir") != /root/* ]]; then
  printf 'Output directory must be a real directory under /root.\n' >&2
  exit 2
fi
chmod 700 -- "$output_dir"
host=$(hostname)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
snapshot="$output_dir/${host}-${role}-${stamp}.tsv"
if [[ -e $snapshot ]]; then
  printf 'Snapshot already exists: %s\n' "$snapshot" >&2
  exit 2
fi
set -C

emit() { printf '%s\t%s\n' "$1" "$2"; }
capture() {
  local label=$1 output line count=0
  shift
  if ! command -v "$1" >/dev/null 2>&1; then emit unavailable "$label: $1 missing"; return; fi
  if output=$("$@" 2>&1); then
    if [[ -z $output ]]; then emit "$label" '(none)'; return; fi
    while IFS= read -r line || [[ -n $line ]]; do
      count=$((count + 1))
      if ((count > 200)); then emit truncated "$label: more than 200 lines"; break; fi
      emit "$label" "$line"
    done <<< "$output"
  else
    emit unavailable "$label: $output"
  fi
}
service() {
  local name=$1 status
  if ! command -v systemctl >/dev/null 2>&1; then emit unavailable 'systemctl missing'; return; fi
  status=$(systemctl is-active "$name" 2>&1) || :
  emit service "$name: ${status:-unavailable}"
}

{
  emit schema 1
  emit role "$role"
  emit host "$host"
  capture people who
  capture listeners ss -H -tulnp
  capture outbound-web ss -H -tnp state established '( dport = :80 or dport = :443 )'
  capture disk df -P /
  capture addresses ip -o -4 addr show
  capture admin-wheel getent group wheel
  capture admin-sudo getent group sudo
  service rsyslog
  service auditd
  case "$role" in
    ecom)
      capture firewall firewall-cmd --list-all
      service httpd
      service mariadb ;;
    email)
      capture firewall ufw status
      service postfix
      service dovecot
      capture mail-queue mailq ;;
    splunk)
      capture firewall nft list ruleset
      if [[ -x /opt/splunk/bin/splunk ]]; then capture splunk /opt/splunk/bin/splunk status
      else emit unavailable 'splunk: /opt/splunk/bin/splunk missing'; fi
      capture splunk-apps ls -lt /opt/splunk/etc/apps ;;
    workstation)
      capture firewall ufw status ;;
  esac
} > "$snapshot"
chmod 600 -- "$snapshot"
printf 'Snapshot: %s\n' "$snapshot"
printf 'Review every changed line against the %s runbook Watch table. A difference is a lead, not an incident.\n' "$role"

if [[ -n $baseline ]]; then
  if ! grep -Fxq -- "$(printf 'role\t%s' "$role")" "$baseline" ||
     ! grep -Fxq -- "$(printf 'host\t%s' "$host")" "$baseline"; then
    printf 'Baseline host or role differs; comparison refused.\n' >&2
    exit 4
  fi
  diff -u -- "$baseline" "$snapshot" || status=$?
  if [[ ${status:-0} -gt 1 ]]; then exit "$status"; fi
fi
