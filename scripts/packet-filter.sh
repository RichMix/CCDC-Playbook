#!/usr/bin/env bash
#===============================================================================
# packet-filter.sh  --  stateful host firewall for CCDC blue-team hosts
#-------------------------------------------------------------------------------
# A dedicated, auditable packet filter you can version and tweak, separate from
# the lighter egress clamp baked into harden-linux.sh. nftables-first with an
# iptables fallback. Default-deny both directions; conntrack state matching;
# anti-spoof; rate-limited SYN + ICMP so a flood can't drown the services you
# are scored on; clean log-then-drop.
#
# CCDC GUARDRAILS (same as the hardening playbook):
#   * ICMP echo is ALLOWED (just rate-limited) -- the box still answers ping.
#   * Scored INBOUND services are open to ALL sources -- no source filtering,
#     no "scoring engine only" allowlist.
#   * The clamp is on EGRESS: only DNS/NTP/HTTP/HTTPS go out, rest is dropped,
#     so a popped host can't call home.
#
# THE LOCKOUT PROBLEM:
#   Loading a default-deny ruleset on a box you reach over SSH is the classic
#   way to lock yourself out. Two protections:
#     1. The current SSH session survives because ct state established is
#        accepted and the SSH port is in the inbound set.
#     2. `--test` applies the rules but schedules an automatic rollback (via
#        systemd-run) after a timeout UNLESS you confirm with `--commit`.
#
# USAGE:
#   sudo ./packet-filter.sh                      # DRY-RUN: print the ruleset only
#   sudo ./packet-filter.sh --test               # apply, auto-rollback in 60s
#   sudo ./packet-filter.sh --commit             # apply + cancel rollback + persist
#   sudo ./packet-filter.sh --apply              # apply + persist immediately (local/confident)
#   sudo ./packet-filter.sh --flush              # remove our table/rules
#
#   Tune what's open (defaults shown):
#   sudo ./packet-filter.sh --apply \
#        --in-tcp "22 80 443" \                  # inbound scored TCP ports
#        --eg-tcp "53 80 443" --eg-udp "53 123" \# allowed outbound TCP/UDP
#        --timeout 60 \                          # --test rollback window (sec)
#        --backend nft                           # force nft|iptables
#===============================================================================

set -uo pipefail   # -u catch typos; NOT -e so one probe can't abort the run.

#------------------------------------------------------------------------------
# Config / args
#------------------------------------------------------------------------------
ACTION="dryrun"                 # dryrun | test | commit | apply | flush
IN_TCP="22 80 443"              # inbound scored TCP ports (open to all sources)
EG_TCP="53 80 443"             # allowed outbound TCP ports
EG_UDP="53 123"               # allowed outbound UDP ports (DNS, NTP)
TIMEOUT=60                     # --test auto-rollback window, seconds
BACKEND=""                     # "" = autodetect; else nft|iptables

while [[ $# -gt 0 ]]; do
  case "$1" in
    --test)     ACTION="test" ;;
    --commit)   ACTION="commit" ;;
    --apply)    ACTION="apply" ;;
    --flush)    ACTION="flush" ;;
    --in-tcp)   IN_TCP="${2:-}"; shift ;;
    --eg-tcp)   EG_TCP="${2:-}"; shift ;;
    --eg-udp)   EG_UDP="${2:-}"; shift ;;
    --timeout)  TIMEOUT="${2:-}"; shift ;;
    --backend)  BACKEND="${2:-}"; shift ;;
    -h|--help)  grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

[[ "$(id -u)" -eq 0 ]] || { echo "[!] run as root (sudo)." >&2; exit 1; }

# Pick a backend: nftables preferred (modern default on RHEL9/Deb12/Arch).
if [[ -z "$BACKEND" ]]; then
  if   command -v nft >/dev/null 2>&1;      then BACKEND="nft"
  elif command -v iptables >/dev/null 2>&1; then BACKEND="iptables"
  else echo "[!] neither nft nor iptables found." >&2; exit 1; fi
fi

BAK="/root/fw-backup-$(date +%Y%m%d-%H%M%S)"   # pre-change ruleset snapshot
log() { echo -e "$*"; }

#------------------------------------------------------------------------------
# nftables ruleset generator -- prints the full table to stdout.
# Using named sets means you edit ONE line to open/close a port later.
#------------------------------------------------------------------------------
nft_ruleset() {
  # Turn "22 80 443" into "22, 80, 443" for nft set syntax.
  local in_tcp="${IN_TCP// /, }"
  local eg_tcp="${EG_TCP// /, }"
  local eg_udp="${EG_UDP// /, }"
  cat <<NFT
# CCDC host firewall -- managed by packet-filter.sh. Edit the sets, not the chains.
table inet ccdc_fw {
  set in_tcp  { type inet_service; flags interval; elements = { ${in_tcp} } }
  set eg_tcp  { type inet_service; flags interval; elements = { ${eg_tcp} } }
  set eg_udp  { type inet_service; flags interval; elements = { ${eg_udp} } }

  chain inbound {
    type filter hook input priority 0; policy drop;   # default-deny inbound

    iif "lo" accept                                   # loopback always
    ct state established,related accept               # keep live sessions (your SSH)
    ct state invalid drop                             # malformed / out-of-state

    # ICMP: answer ping but cap the rate so an echo flood can't saturate us.
    ip  protocol icmp icmp type echo-request limit rate 10/second accept
    ip  protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
    ip6 nexthdr ipv6-icmp accept                      # NDP etc. -- needed for IPv6

    # Scored services: open to ALL sources. Rate-limit only NEW connections
    # (SYN) so a SYN flood is blunted while legitimate clients still connect.
    tcp flags & (fin|syn|rst|ack) == syn tcp dport @in_tcp limit rate 60/second accept
    ct state new tcp dport @in_tcp accept

    limit rate 5/minute log prefix "FW-IN-DROP: " level info   # sampled, not log-flooded
    drop
  }

  chain outbound {
    type filter hook output priority 0; policy drop;  # default-deny egress = no C2

    oif "lo" accept
    ct state established,related accept
    udp dport @eg_udp accept                          # DNS, NTP
    tcp dport @eg_tcp accept                           # DNS/TCP, HTTP, HTTPS (updates)
    ip  protocol icmp accept                           # outbound ping / path MTU
    ip6 nexthdr ipv6-icmp accept

    limit rate 5/minute log prefix "FW-OUT-DROP: " level info
    drop
  }

  chain forward {
    type filter hook forward priority 0; policy drop; # not a router -- drop transit
  }
}
NFT
}

#------------------------------------------------------------------------------
# iptables ruleset -- same policy, emitted as commands (fallback path).
#------------------------------------------------------------------------------
ipt_apply() {
  # Flush our own view and set default-deny; established keeps the SSH session.
  iptables -P FORWARD DROP
  iptables -F; iptables -X 2>/dev/null

  # INPUT: default drop, then allow-list.
  iptables -P INPUT DROP
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
  # ICMP echo, rate-limited (-m limit): still answers ping, flood-resistant.
  iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/sec -j ACCEPT
  iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
  iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
  # Scored TCP ports open to all; SYN rate-limited.
  for p in $IN_TCP; do
    iptables -A INPUT -p tcp --dport "$p" --syn -m limit --limit 60/sec -j ACCEPT
    iptables -A INPUT -p tcp --dport "$p" -m conntrack --ctstate NEW -j ACCEPT
  done
  iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "FW-IN-DROP: "

  # OUTPUT: default drop, egress allow-list.
  iptables -P OUTPUT DROP
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  for p in $EG_UDP; do iptables -A OUTPUT -p udp --dport "$p" -j ACCEPT; done
  for p in $EG_TCP; do iptables -A OUTPUT -p tcp --dport "$p" -j ACCEPT; done
  iptables -A OUTPUT -p icmp -j ACCEPT
  iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "FW-OUT-DROP: "
}

#------------------------------------------------------------------------------
# Backup / restore / persist helpers
#------------------------------------------------------------------------------
backup_rules() {
  if [[ "$BACKEND" == "nft" ]]; then nft list ruleset > "$BAK" 2>/dev/null
  else iptables-save > "$BAK" 2>/dev/null; fi
  log "[*] current ruleset backed up to $BAK"
}
apply_rules() {
  if [[ "$BACKEND" == "nft" ]]; then nft_ruleset | nft -f -
  else ipt_apply; fi
}
persist_rules() {
  if [[ "$BACKEND" == "nft" ]]; then
    nft_ruleset > /etc/nftables.conf                 # loaded by nftables.service
    systemctl enable nftables >/dev/null 2>&1
  else
    # Path differs by distro; try both common savers.
    { iptables-save > /etc/iptables/rules.v4; } 2>/dev/null \
      || { iptables-save > /etc/sysconfig/iptables; } 2>/dev/null
  fi
  log "[+] ruleset persisted (survives reboot)"
}
schedule_rollback() {
  # systemd-run survives this script exiting (unlike a backgrounded subshell),
  # so the revert fires even after your shell closes. --commit cancels it.
  if [[ "$BACKEND" == "nft" ]]; then
    systemd-run --on-active="${TIMEOUT}" --unit=fw-rollback \
      nft -f "$BAK" >/dev/null 2>&1
  else
    systemd-run --on-active="${TIMEOUT}" --unit=fw-rollback \
      bash -c "iptables-restore < '$BAK'" >/dev/null 2>&1
  fi
}
cancel_rollback() {
  systemctl stop fw-rollback.timer 2>/dev/null
  systemctl reset-failed fw-rollback.service fw-rollback.timer 2>/dev/null
  log "[*] pending auto-rollback cancelled"
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------
log "backend: $BACKEND   inbound TCP: [$IN_TCP]   egress TCP:[$EG_TCP] UDP:[$EG_UDP]"

case "$ACTION" in
  dryrun)
    log "== DRY RUN -- ruleset below, nothing applied. Review, then --test. =="
    if [[ "$BACKEND" == "nft" ]]; then nft_ruleset
    else log "(iptables backend: run with --test/--apply to emit live rules)"; fi ;;

  test)
    # Apply now, but auto-revert in $TIMEOUT unless you --commit. Lockout-safe.
    backup_rules
    apply_rules && log "[>>] rules APPLIED"
    schedule_rollback
    log "[!] AUTO-ROLLBACK in ${TIMEOUT}s. If you still have access and all"
    log "    scored services respond, lock it in with:"
    log "        sudo $0 --commit"
    log "    Do nothing and the box reverts to its previous ruleset automatically." ;;

  commit)
    # Confirm a --test run: cancel the timer and write the config to disk.
    cancel_rollback
    apply_rules && log "[>>] rules re-applied"
    persist_rules ;;

  apply)
    # One-shot for when you're local or confident: apply + persist, no rollback.
    backup_rules
    apply_rules && log "[>>] rules APPLIED"
    persist_rules
    log "    (no auto-rollback in --apply mode; backup at $BAK if you need to revert)" ;;

  flush)
    if [[ "$BACKEND" == "nft" ]]; then
      nft delete table inet ccdc_fw 2>/dev/null && log "[*] ccdc_fw table removed"
    else
      iptables -P INPUT ACCEPT; iptables -P OUTPUT ACCEPT; iptables -P FORWARD ACCEPT
      iptables -F; log "[*] iptables flushed to ACCEPT"
    fi ;;
esac

log "\nTip: watch what the filter is dropping ->  journalctl -k | grep 'FW-.*-DROP'"
log "     if a SCORED service also dials OUT (DB on another host, API), add its"
log "     port with --eg-tcp / --eg-udp or that check breaks."
