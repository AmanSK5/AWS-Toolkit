#!/usr/bin/env python3
"""
Finds EBS snapshots that are wasting money:
  - orphaned: source volume no longer exists
  - stale: older than N days (default 90)

Three modes:
  (default)     just report what's there and estimated costs
  --dry-run     show exactly which snapshots would be deleted, but don't touch anything
  --delete      actually delete them (asks for confirmation first)

Runs across single/multiple AWS accounts using the same role-assumption pattern
as the idle cost audit script. Estimates monthly storage cost using
the standard EBS snapshot rate (~£0.05/GB-month for most regions).
"""
import argparse
import boto3
import sys
import warnings
from datetime import datetime, timezone
from botocore.exceptions import ClientError

warnings.filterwarnings("ignore", message=r".*Boto3 will no longer support Python 3\.9.*")

SNAP_PER_GB = 0.05  # rough £/GB-month for snapshot storage
#If you only have one account, replace the one below with your own, if you have multiple, you can add them as per test one
ACCOUNTS = {
    "AmanProd":              "112345678910113",
  # "AmanTest":              "xxxxx",
    
}

USEFUL_TAG_KEYS = ["Name", "Owner", "Environment", "Project"]


def days_since(dt):
    if not dt:
        return None
    return (datetime.now(timezone.utc) - dt).days


def summarise_tags(tags):
    if not tags:
        return ""
    by_key = {t["Key"]: t.get("Value", "") for t in tags if t.get("Key")}
    bits = [f"{k}={by_key[k]}" for k in USEFUL_TAG_KEYS if by_key.get(k)]
    return "; ".join(bits)


def assume_role(account_id, role_name):
    creds = boto3.client("sts").assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
        RoleSessionName="snapshot-audit",
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def enabled_regions(session):
    resp = session.client("ec2", region_name="us-east-1").describe_regions(AllRegions=True)
    return sorted(
        r["RegionName"] for r in resp["Regions"]
        if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")
    )


def _pages(client, method, **kwargs):
    for page in client.get_paginator(method).paginate(**kwargs):
        yield page


def get_live_volume_ids(ec2):
    """Grab all volume IDs that currently exist so we can spot orphans."""
    vids = set()
    for page in _pages(ec2, "describe_volumes"):
        for v in page["Volumes"]:
            vids.add(v["VolumeId"])
    return vids


def scan_region(session, region, owner_id, max_age_days):
    ec2 = session.client("ec2", region_name=region)

    orphaned = []
    stale = []
    orphan_cost = 0.0
    stale_cost = 0.0

    try:
        live_vols = get_live_volume_ids(ec2)
    except ClientError:
        return 0.0, 0.0, [], []

    try:
        for page in _pages(ec2, "describe_snapshots", OwnerIds=[owner_id]):
            for snap in page["Snapshots"]:
                sid = snap["SnapshotId"]
                vol_id = snap.get("VolumeId", "")
                size = snap.get("VolumeSize", 0)
                started = snap.get("StartTime")
                age = days_since(started)
                tags = summarise_tags(snap.get("Tags"))
                monthly = size * SNAP_PER_GB

                age_str = f"{age}d" if age is not None else "?d"
                line = f"[{region}] {sid} vol={vol_id or 'n/a'} age={age_str} {size}GB ~£{monthly:.2f}/mo"
                if tags:
                    line += f"  tags[{tags}]"

                entry = {"snap_id": sid, "region": region, "line": line, "monthly": monthly}

                if vol_id and vol_id not in live_vols:
                    orphan_cost += monthly
                    orphaned.append(entry)
                elif age is not None and age > max_age_days:
                    stale_cost += monthly
                    stale.append(entry)
    except ClientError:
        pass

    return orphan_cost, stale_cost, orphaned, stale


def delete_snapshots(session, entries, dry_run=False):
    """Delete a list of snapshots grouped by region. Returns (deleted, failed) counts."""
    by_region = {}
    for e in entries:
        by_region.setdefault(e["region"], []).append(e)

    deleted = 0
    failed = 0

    for region, snaps in sorted(by_region.items()):
        ec2 = session.client("ec2", region_name=region)
        for s in snaps:
            sid = s["snap_id"]
            if dry_run:
                print(f"    [DRY RUN] would delete {sid} ({region})")
                deleted += 1
                continue
            try:
                ec2.delete_snapshot(SnapshotId=sid)
                print(f"    deleted {sid} ({region})")
                deleted += 1
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                print(f"    FAILED {sid} ({region}): {code} - {e}")
                failed += 1

    return deleted, failed


def main():
    ap = argparse.ArgumentParser(description="EBS snapshot audit across accounts.")
    ap.add_argument("--role-name", required=True, help="IAM role to assume in each account")
    ap.add_argument("--skip-accounts", default="AmanTest,AmanTest2", help="Comma separated account names to skip")
    ap.add_argument("--max-age-days", type=int, default=90,
                    help="Flag non-orphan snapshots older than this (default 90)")

    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true",
                      help="Show what would be deleted, don't actually touch anything")
    mode.add_argument("--delete", action="store_true",
                      help="Actually delete the flagged snapshots")

    args = ap.parse_args()

    if args.delete:
        print("WARNING: this will permanently delete snapshots across all scanned accounts.")
        print("There is no undo. Type 'yes' to continue.")
        confirm = input("> ").strip().lower()
        if confirm != "yes":
            print("Aborted.")
            sys.exit(0)

    skip = {s.strip() for s in args.skip_accounts.split(",") if s.strip()}
    total_orphan = 0.0
    total_stale = 0.0
    total_deleted = 0
    total_failed = 0

    for acct_name, acct_id in ACCOUNTS.items():
        if acct_name in skip:
            continue

        print(f"\n=== {acct_name} ({acct_id}) ===")
        try:
            sess = assume_role(acct_id, args.role_name)
        except Exception as e:
            print(f"  couldn't assume role: {e}")
            continue

        acct_orphaned = []
        acct_stale = []
        acct_orphan_cost = 0.0
        acct_stale_cost = 0.0

        for region in enabled_regions(sess):
            oc, sc, orphaned, stale = scan_region(sess, region, acct_id, args.max_age_days)
            acct_orphan_cost += oc
            acct_stale_cost += sc
            acct_orphaned.extend(orphaned)
            acct_stale.extend(stale)

        if not acct_orphaned and not acct_stale:
            print("  no snapshots found — £0.00/mo")
            continue

        if acct_orphaned:
            print(f"  Orphaned (source volume gone, {len(acct_orphaned)} snapshots):")
            for entry in acct_orphaned:
                print(f"    {entry['line']}")

        if acct_stale:
            print(f"  Stale (>{args.max_age_days} days, {len(acct_stale)} snapshots):")
            for entry in acct_stale:
                print(f"    {entry['line']}")

        print(f"  Est. savings: £{acct_orphan_cost:.2f}/mo orphaned, £{acct_stale_cost:.2f}/mo stale")

        if args.dry_run or args.delete:
            all_snaps = acct_orphaned + acct_stale
            if all_snaps:
                d, f = delete_snapshots(sess, all_snaps, dry_run=args.dry_run)
                total_deleted += d
                total_failed += f

        total_orphan += acct_orphan_cost
        total_stale += acct_stale_cost

    print(f"\n{'='*40}")
    print(f"TOTAL: £{total_orphan:.2f}/mo orphaned + £{total_stale:.2f}/mo stale = £{total_orphan + total_stale:.2f}/mo")

    if args.dry_run:
        print(f"DRY RUN: {total_deleted} snapshots would be deleted")
    elif args.delete:
        print(f"DELETED: {total_deleted} snapshots removed, {total_failed} failed")

    print(f"{'='*40}")


if __name__ == "__main__":
    main()