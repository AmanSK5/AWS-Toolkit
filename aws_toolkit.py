#!/usr/bin/env python3
"""
Quick launcher for the AWS audit/cleanup scripts.
Keeps everything in one place so you don't have to remember filenames and flags.
"""
import os
import subprocess
import sys

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")

MENU = [
    ("Idle resource audit",    "multi_account_idle_report.py"),
    ("Snapshot audit (report)", "snapshot_audit.py"),
    ("Snapshot audit (dry run)", "snapshot_audit.py", ["--dry-run"]),
    ("Snapshot audit (DELETE)",  "snapshot_audit.py", ["--delete"]),
    ("IAM user activity report", "iam_console_activity_report.py"),
]


def prompt_role():
    role = input("Role name to assume (e.g. CrossAccountAdmin): ").strip()
    if not role:
        print("No role provided, aborting.")
        sys.exit(1)
    return role


def prompt_skip():
    skip = input("Accounts to skip [ReedAI]: ").strip()
    return skip if skip else "ReedAI"


def run_script(entry, common_args):
    name = entry[0]
    script = os.path.join(SCRIPTS_DIR, entry[1])
    extra = entry[2] if len(entry) > 2 else []

    if not os.path.exists(script):
        print(f"\n  Can't find {script} — skipping.")
        return

    # IAM script doesn't use --role-name, pipes through column for readability
    if "iam" in entry[1].lower():
        cmd_str = f"{sys.executable} {script} --outdir stdout | column -t -s,"
        print(f"\n--- running: {cmd_str} ---\n")
        subprocess.run(cmd_str, shell=True)
    else:
        cmd = [sys.executable, script,
               "--role-name", common_args["role"],
               "--skip-accounts", common_args["skip"]]
        cmd.extend(extra)
        print(f"\n--- running: {' '.join(cmd)} ---\n")
        subprocess.run(cmd)


def main():
    while True:
        print("\n\033[33m=== AWS Audit Toolkit ===\033[0m")
        for i, entry in enumerate(MENU, 1):
            print(f"  {i}) {entry[0]} ({entry[1]})")
        print("  Q) Quit")

        choice = input("Select: ").strip().lower()
        if choice == "q":
            break

        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(MENU):
                raise ValueError
        except ValueError:
            print("Invalid choice.")
            continue

        entry = MENU[idx]

        # only ask for role/skip if the script needs it
        if "iam" in entry[1].lower():
            common_args = {}
        else:
            common_args = {"role": prompt_role(), "skip": prompt_skip()}

        run_script(entry, common_args)


if __name__ == "__main__":
    main()