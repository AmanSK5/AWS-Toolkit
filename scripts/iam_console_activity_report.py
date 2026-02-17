#!/usr/bin/env python3
import argparse
import csv
import io
import os
import sys
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


def parse_dt(value):
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    try:
        v = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def days_ago(dt):
    if dt is None:
        return ""
    now = datetime.now(timezone.utc)
    return (now - dt).days


def load_exclusions(path):
    if not path or not os.path.exists(path):
        return set()
    s = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            name = line.strip()
            if name and not name.startswith("#"):
                s.add(name)
    return s


def get_current_iam_users(iam):
    users = set()
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for u in page.get("Users", []):
            users.add(u.get("UserName"))
    return users


def get_credential_report(iam, max_wait_seconds=60, poll_seconds=2):
    """
    Generates IAM credential report and waits until it's ready.
    Note: AWS may still return a cached report (can be up to ~4h old).
    """
    iam.generate_credential_report()

    start = time.time()
    while True:
        try:
            rep = iam.get_credential_report()
            content = rep["Content"].decode("utf-8")
            return list(csv.DictReader(io.StringIO(content)))
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("ReportInProgress", "CredentialReportNotReadyException"):
                if (time.time() - start) > max_wait_seconds:
                    raise RuntimeError(
                        "Credential report still not ready after %ss. Try again or increase max_wait_seconds."
                        % max_wait_seconds
                    )
                time.sleep(poll_seconds)
                continue
            raise


def most_recent_datetime(dts):
    dts = [d for d in dts if d is not None]
    return max(dts) if dts else None


def main():
    ap = argparse.ArgumentParser(description="IAM console last sign-in + last activity report (Python 3.8/3.9 compatible).")
    ap.add_argument("--exclude-file", default="service_accounts.txt",
                    help="File with usernames to exclude (one per line). Default: service_accounts.txt")
    ap.add_argument("--include-root", action="store_true", help="Include <root_account> row")
    ap.add_argument("--outdir", default="out", help="Output directory OR 'stdout' to print")
    ap.add_argument("--outfile", default="iam_console_activity_report.csv", help="Output CSV filename")
    ap.add_argument("--max-wait", type=int, default=90, help="Max seconds to wait for credential report")
    ap.add_argument("--poll", type=int, default=2, help="Poll interval seconds")

    ap.add_argument("--skip-deleted", dest="skip_deleted", action="store_true", default=True,
                    help="Skip users that no longer exist (default: enabled).")
    ap.add_argument("--no-skip-deleted", dest="skip_deleted", action="store_false",
                    help="Do not skip deleted users (shows cached credential report entries).")

    args = ap.parse_args()

    if args.outdir != "stdout":
        os.makedirs(args.outdir, exist_ok=True)

    session = boto3.Session(profile_name=os.getenv("AWS_PROFILE") or None)
    iam = session.client("iam")

    excludes = load_exclusions(args.exclude_file)

    current_users = get_current_iam_users(iam) if args.skip_deleted else None
    rows = get_credential_report(iam, max_wait_seconds=args.max_wait, poll_seconds=args.poll)

    out_path = os.path.join(args.outdir, args.outfile)

    fields = [
        "user",
        "password_enabled",
        "mfa_active",
        "console_last_sign_in",         # password_last_used
        "console_last_sign_in_days",
        "last_activity",               # max(password_last_used, access_key_1_last_used_date, access_key_2_last_used_date)
        "last_activity_days",
    ]

    report = []

    for r in rows:
        user = r.get("user")

        # Filter out deleted users (credential report can be stale)
        if args.skip_deleted and user not in ("<root_account>",):
            if user not in current_users:
                continue

        if user == "<root_account>":
            if not args.include_root:
                continue
        else:
            if user in excludes:
                continue

        password_enabled = r.get("password_enabled")  # "true"/"false"
        mfa_active = r.get("mfa_active")              # "true"/"false"

        console_last = parse_dt(r.get("password_last_used"))

        # API activity (not showing key IDs, just the last used dates from the credential report)
        ak1_last = parse_dt(r.get("access_key_1_last_used_date"))
        ak2_last = parse_dt(r.get("access_key_2_last_used_date"))

        last_activity = most_recent_datetime([console_last, ak1_last, ak2_last])

        report.append({
            "user": user,
            "password_enabled": password_enabled,
            "mfa_active": mfa_active,
            "console_last_sign_in": console_last.isoformat() if console_last else "",
            "console_last_sign_in_days": days_ago(console_last),
            "last_activity": last_activity.isoformat() if last_activity else "",
            "last_activity_days": days_ago(last_activity),
        })

    # Sort: stalest at top (never activity first), then oldest -> newest
    def sort_key(x):
        days = x.get("last_activity_days")
        if days == "":
            return -1  # never seen activity
        return int(days)

    report.sort(key=sort_key, reverse=True)

    if args.outdir == "stdout":
        w = csv.DictWriter(sys.stdout, fieldnames=fields)
        w.writeheader()
        w.writerows(report)
    else:
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(report)
        print("Wrote: %s" % out_path)


if __name__ == "__main__":
    main()