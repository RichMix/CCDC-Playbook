# Linux hardening playbook

These scripts are templates for authorized CCDC blue-team work. Inventory first,
map dependencies, keep console access, and verify the required service paths
after every change. Neither script has been validated against a live competition
image.

For manual review and cleanup of cron jobs, services, and firewall openings,
use the [audit and retirement guide](../guides/retire-unneeded-jobs-services-ports.md).

| Script | Scope |
| --- | --- |
| [`harden-ecom.sh`](harden-ecom.sh) | Rocky Linux 9 store host. Captures an inventory by default and makes higher-risk controls opt-in. |
| [`harden-linux.sh`](harden-linux.sh) | Portable persistence hunt and broad hardening for other Linux hosts. Generic `--apply` requires `--ack-generic-apply` after host-specific review. |
| [`packet-filter.sh`](packet-filter.sh) | Standalone stateful firewall (nftables/iptables). Prints the ruleset by default; `--test` applies with an automatic rollback so a bad rule can't lock you out. Required inbound services and ICMP echo stay open; egress clamp and default-deny are the applied modes, not the dry-run. |
| [`fim.sh`](fim.sh) | File-integrity monitor. Baselines known-good hashes and reports additions, changes, and removals outside an ignore-list. Detection only — it changes nothing — and installs as a systemd timer that logs drift to syslog. |
| [`runbook-watch.sh`](runbook-watch.sh) | Read-only watch snapshot for a Linux host (`ecom`, `email`, `splunk` or `workstation`): people, listeners, outbound web connections, disk, admin groups, logging and the role's services. Writes a mode-600 TSV under `/root/ccdc-watch/` and can diff against an earlier one with `--baseline`. Changes nothing. |
| [`runbook-watch.ps1`](runbook-watch.ps1) | The same for Windows (`-Role AD`, `MSSQL` or `Wkst`): sessions, listeners, admins, non-Microsoft tasks, firewall, Defender, the Splunk forwarder and role services. Writes JSON under `%LOCALAPPDATA%\CCDC\Reports` and can diff with `-BaselinePath`. Changes nothing. |

## What changed from Claude's original draft

The earlier e-commerce profile invoked the portable script's full `--apply`
path before changing the web and database services. This version gives the
Rocky profile its own inventory and apply sequence.

| Earlier behavior | Revised Rocky profile |
| --- | --- |
| Generic SSH, kernel, firewall, PHP, and MAC changes ran first. | Baseline is scoped to Rocky 9 and requires an explicit active firewalld interface and zone. |
| Outbound traffic became default deny with a small allowlist. | Outbound deny is opt-in with `--enable-egress` after mapping DNS, time, updates, payment, mail, database, and logging flows. |
| PHP functions and SELinux web booleans were changed globally. | Current settings are recorded for review; the script does not toggle them wholesale. |
| Apache was restarted and webroot permissions changed recursively. | No web service restart or webroot mutation. |
| Database bind address, grants, and service state were changed. | No automatic database changes. |
| Password and root SSH behavior followed the generic script. | `--key-only` requires a preflighted admin key; `--deny-root-ssh` is separate. The baseline preserves existing password and root login settings. |
| Broad inbound and reverse-path filtering could affect availability. | Required inbound services are added without source filters; pruning is opt-in. Strict `rp_filter` is not forced and ICMP echo is not blocked. |

The portable script remains available for investigation. Its apply path is
broad: it can change SSH, kernel settings, password policy, audit rules, and
services. Review its full output and test on a matching lab host before using
`--ack-generic-apply`. Outbound deny, PHP function restrictions, and MAC
changes require their own flags.

### Portable script flags

| Flag | Effect |
| --- | --- |
| `--apply --ack-generic-apply` | Apply the generic baseline after host-specific review. The default run is report-only. |
| `--hunt-only` | Report persistence indicators and stop before hardening. |
| `--ssh-key "KEY"` | Install the supplied public key before switching SSH password authentication off. In report-only mode it only describes this action. |
| `--enable-egress` | Opt in to outbound default deny. Off by default. Map application dependencies first. |
| `--out-ports PORT/PROTO,...` | Outbound allowlist for `--enable-egress`; defaults to `53/udp,53/tcp,123/udp,80/tcp,443/tcp`. It accepts TCP and UDP ports from 1 to 65535. |
| `--php-disable-functions` | Opt in to appending a PHP `disable_functions` list. Off by default; without it the script reports current declarations and does not edit `php.ini` or restart web/PHP services. With it, validate and restart the relevant web SAPI manually. |
| `--enable-mac` | Opt in to SELinux or AppArmor changes, including web booleans; off by default. |
| `--force-family rhel\|debian\|arch` | Override OS-family detection. |

The portable firewalld direct and iptables egress backends cover IPv4 only;
inspect IPv6 separately. Its PHP inventory starts with the CLI primary ini and
Debian per-SAPI files, so verify the effective web SAPI configuration before
enabling `--php-disable-functions`.

## Rocky workflow

Run these commands from the repository root on the Rocky host. Inventory writes
private evidence under `/root/ccdc-hardening/` without changing host settings.

```bash
sudo bash scripts/harden-ecom.sh
sudo ls -dt /root/ccdc-hardening/* | head
ip -br address
sudo firewall-cmd --get-active-zones
```

Review listeners, accounts, keys, firewall state, SELinux booleans, and store
dependencies. Once the production interface is identified, apply the baseline:

```bash
sudo bash scripts/harden-ecom.sh --apply --interface <interface>
```

The default inbound services are `ssh,http,https`. Add any other required
service or port through `--in-services` and `--in-ports`. Test remote SSH,
HTTP/HTTPS content, ping, and the full store workflow immediately after apply.

| Optional flag | Use only after |
| --- | --- |
| `--admin USER --key-only` | A working second SSH session proves key login, and password login is not required. |
| `--deny-root-ssh` | Root SSH is not required for operations or service checks. |
| `--prune-inbound` | Every required inbound service has been mapped and listed. |
| `--enable-egress --out-ports CSV` | All outbound application dependencies are mapped and tested, including IPv6. |

Each run records a baseline, run log, after-state, and backups of overwritten
files. A newly created file has no previous copy; remove it to undo that file.
Firewalld changes also require inspecting the saved zone and policy state before
rollback.

## IDS, IPS, decoys, and packet visibility

Start web and host detection in alert-only mode. Review alerts against normal
store traffic and service checks before enabling any block rule. Keep decoys on
non-required ports and paths. Packet mirroring needs control of an existing
network device or sensor path; this host script does not configure a switch or
create a sensor VM. Use scoped host logs or a short authorized packet capture
when a mirror is unavailable.

Two standalone host tools support this work. `packet-filter.sh` is a dedicated
stateful firewall: review its ruleset with the default dry-run, then apply it
with `--test` (which auto-rolls-back after a timeout unless you `--commit`), so
you never lose console access to a bad rule. `fim.sh` is a detection-only
file-integrity monitor — baseline the host once it is known-good, then run
`--check` or `--install` to be alerted when files drift outside your whitelist.
Capture the integrity baseline after hardening, not before.

## Validation

```bash
bash -n scripts/harden-linux.sh scripts/harden-ecom.sh scripts/packet-filter.sh scripts/fim.sh
```

Syntax validation does not prove firewalld policy behavior or application
compatibility. Run inventory and staged apply on a representative Rocky 9 lab
image, then verify SSH, web content, ping, store transactions, dependencies,
and rollback before live use.

## Watch snapshots

Run one on the host itself, with that host's role. Neither script reaches another machine, changes a setting or sends anything anywhere.

```bash
sudo bash scripts/runbook-watch.sh ecom
# Later rounds: compare with a known-good snapshot from the same host and role
sudo bash scripts/runbook-watch.sh ecom --baseline /root/ccdc-watch/HOST-ecom-YYYYMMDDTHHMMSSZ.tsv
```

```powershell
.\scripts\runbook-watch.ps1 -Role AD
.\scripts\runbook-watch.ps1 -Role AD -BaselinePath 'C:\Users\YOU\AppData\Local\CCDC\Reports\HOST-AD-YYYYMMDDTHHMMSSZ.json'
```

`unavailable` (Linux) or a read error (Windows) means a command failed: it is not a pass. The diff isn't filtered, so normal logins and service changes show up too; a new listener, account or task is a lead, not proof. The snapshots hold account names and addresses, so keep them on the host.
