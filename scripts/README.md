# Linux Hardening + Persistence-Hunt Playbook

Blue-team hardening scripts for CCDC. Two flavors, same core logic
(persistence hunt → backup → dry-run gate → harden → egress control →
tripwire):

| Script | Use it on |
|--------|-----------|
| `harden-linux.sh` | **Any** host. Auto-detects RHEL / Debian / Arch family and swaps package manager, firewall, MAC layer, and web paths. Start here. |
| `harden-ecom.sh`  | Rocky 9 "Ecom" web/DB box specifically. Same logic, pre-tuned to that role (httpd/PHP/DB). |

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

## Watch out

- After `--apply`, **test any scored service.** The two things most likely to
  break a real app are the PHP `disable_functions` list and the egress rules
  (if the app makes outbound calls). Both spots print a warning telling you
  which knob to loosen.
- These are **defensive** tools for systems you own or defend in the competition.
