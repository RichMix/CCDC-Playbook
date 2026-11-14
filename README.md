# CCDC-Playbook

Blue-team tooling and notes for the Collegiate Cyber Defense Competition (CCDC).
The focus is fast, safe host hardening — lock a box down and surface attacker
persistence before the red team can settle in, without breaking the services
you're scored on.

## What's here

| Path | What it is |
|------|------------|
| [`scripts/harden-linux.sh`](scripts/harden-linux.sh) | **Portable** hardening + persistence-hunt script. Auto-detects RHEL / Debian / Arch family and swaps package manager, firewall, MAC layer, and web paths. Start here. |
| [`scripts/harden-ecom.sh`](scripts/harden-ecom.sh) | Rocky 9 "Ecom" web/DB box — same logic, pre-tuned to that role. |
| [`scripts/README.md`](scripts/README.md) | Full runbook: every flag, what each step changes, and the gotchas. |

## Quick start

Both scripts **default to dry-run** — they hunt and report, and change nothing
until you pass `--apply`.

```bash
# 1. Report only: inventory + persistence hunt, no changes. Read the red [XX] lines.
sudo ./scripts/harden-linux.sh

# 2. Apply hardening AND install your team key in one go. Passwords are only
#    disabled once a key is in place, so you can't lock yourself out.
sudo ./scripts/harden-linux.sh --apply --ssh-key "ssh-ed25519 AAAA...key... team@host"
```

## Design principles

- **Dry-run by default.** Nothing changes without `--apply`; every edited file
  is backed up under `/root/harden-<timestamp>/backup/` first, so rollback is one `cp`.
- **Don't break what's scored.** ICMP echo stays up and inbound services stay
  open to all sources. The clamp is on **egress** — DNS/NTP/80/443 out, drop and
  log the rest — so a popped host can't call home even with a shell on it.
- **Hunt, don't nuke.** The persistence sweep (rogue accounts, SSH keys, cron,
  systemd units, `.bashrc` callbacks, odd SUID, webshells, `ld.so.preload`)
  *reports* — you decide what's legit before removing it.
- **Watch continuously.** A 5-minute systemd-timer tripwire logs any new
  persistence to syslog: `journalctl -t harden-watch -f`.

## Scope

These are **defensive** tools for hosts you own or are defending in the
competition. See [`scripts/README.md`](scripts/README.md) for the full flag
reference and the two spots most likely to need tuning after `--apply` (the PHP
`disable_functions` list and the egress allowlist).

## Roadmap

- [x] Portable host-hardening + persistence-hunt script
- [x] Rocky 9 Ecom-specific profile
- [ ] Per-role profiles (DNS/mail, AD-join, database) sharing one core library
- [ ] Central log collector so the whole team sees tripwire hits in one place
- [ ] Decoy / honeypot and diversion layer
