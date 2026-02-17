# AWS Audit Toolkit

A collection of Python scripts for auditing idle resources, snapshot cleanup, and IAM user activity across multiple AWS accounts. Includes a menu-based launcher (`aws_toolkit.py`) so everything stays in one place — similar to my [M365 / Entra toolkit](https://github.com/AmanSK5/AAD-automation).

---

## Structure

```
aws_toolkit.py              # menu launcher — sits outside the scripts folder
scripts/
  multi_account_idle_report.py
  snapshot_audit.py
  iam_console_activity_report.py
  service_accounts.txt      # (optional) usernames to exclude from IAM report
```

---

## Prerequisites

- Python 3.8+
- `boto3` installed (`pip install boto3`)
- A cross-account IAM role (e.g. `CrossAccountAdmin`) that can be assumed from your working account
- For the IAM report: `AWS_PROFILE` set or default credentials configured

---

## Usage

Run the launcher from the parent directory:

```bash
python3 aws_toolkit.py
```

You'll get a menu like this:

```
=== AWS Audit Toolkit ===
  1) Idle resource audit (multi_account_idle_report.py)
  2) Snapshot audit (report) (snapshot_audit.py)
  3) Snapshot audit (dry run) (snapshot_audit.py)
  4) Snapshot audit (DELETE) (snapshot_audit.py)
  5) IAM user activity report (iam_console_activity_report.py)
  Q) Quit
Select:
```

After a script finishes it drops you back to the menu. `Q` to exit.

For the cross-account scripts (options 1–4), it'll ask for the role name and which accounts to skip. The IAM report runs against your current AWS profile and pipes through `column -t` automatically.

---

## Scripts

### multi_account_idle_report.py

Scans all accounts for resources that are costing money but probably shouldn't be:

- Stopped EC2 instances (with their EBS still attached)
- Unattached EBS volumes
- Unattached Elastic IPs
- NAT Gateways

Splits EBS volumes into "safe to clean up" vs "needs K8s review" so you don't accidentally delete PVCs that a cluster still expects.

```bash
python3 scripts/multi_account_idle_report.py --role-name CrossAccountAdmin
```

| Flag | Default | Description |
|------|---------|-------------|
| `--role-name` | *(required)* | IAM role to assume in each account |
| `--skip-accounts` | `AmanProd` | Comma-separated account names to skip |
| `--stopped-days` | `30` | Only flag EC2 instances stopped longer than this |
| `--k8s-min-age-days` | `30` | Only show K8s-ish volumes older than this |

---

### snapshot_audit.py

Finds EBS snapshots that are wasting money, in two buckets:

- **Orphaned** — source volume no longer exists (almost always safe to delete)
- **Stale** — older than N days but volume still exists (needs a judgement call)

Has three modes:

```bash
# just report
python3 scripts/snapshot_audit.py --role-name CrossAccountAdmin

# show what would be deleted without touching anything
python3 scripts/snapshot_audit.py --role-name CrossAccountAdmin --dry-run

# actually delete (asks for confirmation first)
python3 scripts/snapshot_audit.py --role-name CrossAccountAdmin --delete
```

| Flag | Default | Description |
|------|---------|-------------|
| `--role-name` | *(required)* | IAM role to assume in each account |
| `--skip-accounts` | `AmanProd` | Comma-separated account names to skip |
| `--max-age-days` | `90` | Flag non-orphan snapshots older than this |
| `--dry-run` | | Show what would be deleted, don't touch anything |
| `--delete` | | Actually delete the flagged snapshots |

---

### iam_console_activity_report.py

Generates a report of IAM user activity — last console sign-in, last API activity, MFA status, and password status. Useful for finding accounts that should be cleaned up.

```bash
# output to terminal (how the toolkit runs it)
python3 scripts/iam_console_activity_report.py --outdir stdout | column -t -s,

# output to CSV file
python3 scripts/iam_console_activity_report.py
```

| Flag | Default | Description |
|------|---------|-------------|
| `--exclude-file` | `service_accounts.txt` | File with usernames to skip (one per line) |
| `--include-root` | off | Include the root account row |
| `--outdir` | `out` | Output directory, or `stdout` to print |
| `--outfile` | `iam_console_activity_report.csv` | Output CSV filename |
| `--skip-deleted` | on | Skip users that no longer exist in IAM |

---

## Accounts

The cross-account scripts have the account list hardcoded. To add or remove accounts, edit the `ACCOUNTS` dict at the top of each script.

---

## Notes

- All cost estimates are rough and in GBP (£)
- The snapshot `--delete` flag asks you to type `yes` before it touches anything — there's no undo
- The IAM credential report can be cached by AWS for up to 4 hours, so the data might not be real-time
- Certain accounts are skipped by default via `--skip-accounts` since they're managed separately
