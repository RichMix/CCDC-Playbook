# Linux Hardening + Persistence-Hunt Playbook

Blue-team scripts for CCDC. The two hardening scripts share one core flow
(persistence hunt → backup → dry-run gate → harden → egress control →
tripwire); the firewall and integrity monitor are standalone tools that
complement them.

| Script | Use it on |
|--------|-----------|
| `harden-linux.sh` | **Any** host. Auto-detects RHEL / Debian / Arch family and swaps package manager, firewall, MAC layer, and web paths. Start here. |
| `harden-ecom.sh`  | Rocky 9 "Ecom" web/DB box specifically. Same logic, pre-tuned to that role (httpd/PHP/DB). |
| `packet-filter.sh` | Dedicated stateful firewall (nftables / iptables). Default-deny both ways, rate-limited SYN+ICMP, log-drop, with a lockout-safe `--test` mode. |
| `fim.sh` | File-integrity monitor. Baselines a whitelist of known-good hashes and alerts on drift (added/changed/removed) as a systemd timer. |

## Suggested order on a fresh box

```bash
sudo ./harden-linux.sh                 # 1. hunt + report (read the red lines)
sudo ./harden-linux.sh --apply --ssh-key "ssh-ed25519 AAAA... team@host"  # 2. harden
sudo ./packet-filter.sh --test         # 3. firewall, auto-rolls-back in 60s...
sudo ./packet-filter.sh --commit       #    ...lock it in once services still respond
sudo ./fim.sh --baseline               # 4. snapshot the now-known-good state
sudo ./fim.sh --install                #    run integrity checks every 5 min
```

## Golden rule: dry-run first

Neither script changes anything until you pass `--apply`. The default run
only **hunts and reports** — read the red `[XX]` lines before you commit.

```bash
sudo ./harden-linux.sh            # report only: inventory + persistence hunt, no changes
sudo ./harden-linux.sh --hunt-only # just the persistence hunt, then stop
```

## Applying it (do the SSH key step — it prevents lockout)

```bash
# Apply hardening AND install your team key in one go. Passwords are only
# disabled once a key is in place, so you can't lock yourself out.
sudo ./harden-linux.sh --apply --ssh-key "ssh-ed25519 AAAA...your_key... team@host"
```

Flags:

- `--apply` — actually make changes (otherwise everything is a dry-run preview).
- `--ssh-key "<pubkey>"` — install this key for the sudo user, then switch SSH
  to key-only. **Without this flag the script keeps password auth ON** so a
  missing key never locks you out.
- `--admin <user>` — which account keeps SSH access (defaults to the sudo user).
- `--hunt-only` — run the persistence hunt and exit.
- `--force-family rhel|debian|arch` — override auto-detection if `/etc/os-release`
  is missing or weird (`harden-linux.sh` only).

## What it changes (all backed up first)

Every edited file is copied under `/root/harden-<timestamp>/backup/` before it's
touched, so rollback is one `cp`. Baselines (process/listener/account/package
snapshots) land in `.../baseline/` — diff against them after suspicious activity.

- **SSH** — key-only (once a key exists), no root login, drop-in that sorts
  before vendor defaults.
- **Firewall + egress** — inbound scored services stay open to all sources and
  **ICMP stays up**; the clamp is on *egress* (DNS/NTP/80/443 out, drop + log the
  rest) so a popped host can't call home. Works via firewalld / ufw / nftables /
  iptables depending on what's installed.
- **MAC** — SELinux enforcing + web booteans off (RHEL); AppArmor enforce (Debian).
- **Kernel/sysctl, PHP (exec family disabled), web banners, auditd watches.**
- **Tripwire** — a 5-minute systemd timer (`harden-watch`) that logs any new
  persistence to syslog: `journalctl -t harden-watch -f`.

## `packet-filter.sh` — stateful firewall

A dedicated, auditable ruleset separate from the lighter egress clamp inside the
hardening script. Default-deny inbound **and** outbound, connection tracking,
rate-limited SYN and ICMP (so a flood can't drown the scored services), and a
clean log-then-drop. ICMP echo stays answerable and inbound scored ports stay
open to all sources — the clamp is on egress.

```bash
sudo ./packet-filter.sh                 # dry-run: print the ruleset, change nothing
sudo ./packet-filter.sh --test          # apply, then AUTO-ROLLBACK in 60s unless you...
sudo ./packet-filter.sh --commit        # ...confirm: cancels rollback + persists
sudo ./packet-filter.sh --apply         # apply + persist immediately (local/confident)
sudo ./packet-filter.sh --flush         # remove the ruleset
```

Flags: `--in-tcp "22 80 443"` (inbound scored ports), `--eg-tcp "53 80 443"` /
`--eg-udp "53 123"` (allowed egress), `--timeout 60` (`--test` rollback window),
`--backend nft|iptables`. **`--test` is the safe way to change a firewall on a
remote box** — if a bad rule cuts your access, the box reverts on its own.
Watch drops with `journalctl -k | grep 'FW-.*-DROP'`.

## `fim.sh` — file-integrity monitor (detect changes outside a whitelist)

Keeps a baseline of known-good sha256 hashes (your whitelist) and reports
anything added, changed, or removed against it — minus an ignore-list of paths
that churn on their own.

```bash
sudo ./fim.sh --baseline                # snapshot the known-good state (do this AFTER hardening)
sudo ./fim.sh --check                   # report drift now (exits non-zero if any)
sudo ./fim.sh --install                 # systemd timer: check every 5 min -> syslog
sudo ./fim.sh --accept                  # re-bless the baseline after an APPROVED change
journalctl -t ccdc-fim -f               # watch alerts
```

Flags: `--paths "<dirs>"`, `--ignore "<globs>"`, `--interval <min>`,
`--store <dir>`. The baseline stores its own hash, so tampering with the
baseline file itself is detected.

## Watch out

- After `--apply`, **test any scored service.** The two things most likely to
  break a real app are the PHP `disable_functions` list and the egress rules
  (if the app makes outbound calls). Both spots print a warning telling you
  which knob to loosen.
- Capture the FIM baseline **after** hardening + firewall, so your known-good
  state is the hardened one. If a scored service also dials outbound, add its
  port to the firewall's `--eg-tcp`/`--eg-udp` or that check breaks.
- These are **defensive** tools for systems you own or defend in the competition.
