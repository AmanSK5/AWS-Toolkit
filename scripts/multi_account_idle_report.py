#!/usr/bin/env python3
"""
Scans defined AWS accounts for idle resources that are costing us money:
stopped EC2 instances, unattached EBS volumes, unused EIPs, NAT gateways.

Splits EBS volumes into "safe to delete" vs "needs K8s review" buckets
so we don't accidentally delete PVCs that a cluster still expects.

"""
import argparse
import boto3
import re
import warnings
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# boto3 keeps telling me about python 3.9, this is because of the python version I have on my machine, for other apps
warnings.filterwarnings("ignore", message=r".*Boto3 will no longer support Python 3\.9.*")

# rough per-unit monthly costs in GBP
EBS_PER_GB = 0.08
EIP_COST = 3.60
NAT_COST = 32.00

ACCOUNTS = { #If you only have one account, replace the one below with your own, if you have multiple, you can add them as per test one
    "AmanProd":              "1234567891011",
#   "AmanTest":              "xxxxxxxxxx",

}

# tags worth having in the report
USEFUL_TAG_KEYS = ["Name", "Owner", "Environment", "Env", "CostCenter", "Project", "Application"]

# if any of these show up in tag keys or the Name tag, it's likely k8 related
K8S_TAG_HINTS = [
    "kubernetes.io/cluster/",
    "kubernetes.io/created-for/",
    "KubernetesCluster",
    "eks:cluster-name",
]
K8S_NAME_HINTS = ["dynamic-pvc", "k8s", "kubernetes", "eks"]


def days_since(dt):
    if not dt:
        return None
    return (datetime.now(timezone.utc) - dt).days


def summarise_tags(tags):
    """Pull the tags into a readable string."""
    if not tags:
        return "", {}
    by_key = {t["Key"]: t.get("Value", "") for t in tags if t.get("Key")}
    bits = [f"{k}={by_key[k]}" for k in USEFUL_TAG_KEYS if by_key.get(k)]
    return "; ".join(bits), by_key


def looks_like_k8s(tag_map):
    for key in tag_map:
        if any(hint in key for hint in K8S_TAG_HINTS):
            return True
    name = (tag_map.get("Name") or "").lower()
    return any(hint in name for hint in K8S_NAME_HINTS)


def assume_role(account_id, role_name):
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
        RoleSessionName="idle-cost-audit",
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


def parse_stop_time(reason):
    """Try to pull the timestamp out of StateTransitionReason, e.g.
    'User initiated (2026-01-01 12:34:56 GMT)'"""
    if not reason:
        return None
    m = re.search(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)", reason)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _pages(client, method, **kwargs):
    for page in client.get_paginator(method).paginate(**kwargs):
        yield page


def scan_region(session, region, min_stopped_days, k8s_min_age):
    ec2 = session.client("ec2", region_name=region)
    findings = []       # safe-ish stuff we can just clean up
    k8s_findings = []   # need to check the cluster first, review the ID against things in use via kubectl
    cost = 0.0              # kubectl get pv PVC ID HERE -o jsonpath='{.spec.csi.volumeHandle}{"\n"}'
    k8s_cost = 0.0          # kubectl describe pvc -n FROM THE PVC ID COMMAND ABOVE | sed -n '/Used By:/,/Events:/p'

    # -- stopped instances sitting around with their EBS still attached --
    try:
        for page in _pages(ec2, "describe_instances",
                           Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]):
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    iid = inst["InstanceId"]
                    tag_str, _ = summarise_tags(inst.get("Tags"))

                    stopped_at = parse_stop_time(inst.get("StateTransitionReason", "")) or inst.get("LaunchTime")
                    age = days_since(stopped_at)
                    if age is None or age < min_stopped_days:
                        continue

                    # add up attached volume sizes
                    vol_ids = [
                        bd["Ebs"]["VolumeId"]
                        for bd in inst.get("BlockDeviceMappings", [])
                        if bd.get("Ebs", {}).get("VolumeId")
                    ]
                    total_gb = 0
                    for i in range(0, len(vol_ids), 200):
                        vols = ec2.describe_volumes(VolumeIds=vol_ids[i:i+200])["Volumes"]
                        total_gb += sum(v.get("Size", 0) for v in vols)

                    monthly = total_gb * EBS_PER_GB
                    cost += monthly
                    line = f"[{region}] Stopped EC2 {iid} ({age}d) {total_gb}GB ~£{monthly:.2f}/mo"
                    if tag_str:
                        line += f"  tags[{tag_str}]"
                    findings.append(line)
    except ClientError:
        pass

    # -- unattached EBS volumes --
    try:
        for page in _pages(ec2, "describe_volumes",
                           Filters=[{"Name": "status", "Values": ["available"]}]):
            for v in page["Volumes"]:
                vid = v["VolumeId"]
                size = v.get("Size", 0)
                age = days_since(v.get("CreateTime"))
                tag_str, tag_map = summarise_tags(v.get("Tags"))
                monthly = size * EBS_PER_GB

                k8s = looks_like_k8s(tag_map)
                if k8s and age is not None and age < k8s_min_age:
                    continue  # likely still in use so skip

                label = "EBS (K8s review)" if k8s else "Unattached EBS"
                age_str = f"{age}d" if age is not None else "?d"
                line = f"[{region}] {label} {vid} age={age_str} {size}GB ~£{monthly:.2f}/mo"
                if tag_str:
                    line += f"  tags[{tag_str}]"

                if k8s:
                    k8s_cost += monthly
                    k8s_findings.append(line)
                else:
                    cost += monthly
                    findings.append(line)
    except ClientError:
        pass

    # -- unattached elastic IPs --
    try:
        for eip in ec2.describe_addresses()["Addresses"]:
            if "InstanceId" not in eip and "NetworkInterfaceId" not in eip:
                cost += EIP_COST
                findings.append(f"[{region}] Unattached EIP {eip.get('PublicIp', '?')} ~£{EIP_COST:.2f}/mo")
    except ClientError:
        pass

    # -- NAT gateways (always worth reviewing, they're pricey from what I can see in AWS) --
    try:
        for page in _pages(ec2, "describe_nat_gateways"):
            for nat in page["NatGateways"]:
                if nat.get("State") != "available":
                    continue
                cost += NAT_COST
                findings.append(f"[{region}] NAT Gateway {nat['NatGatewayId']} ~£{NAT_COST:.2f}/mo")
    except ClientError:
        pass

    return cost, k8s_cost, findings, k8s_findings


def main():
    ap = argparse.ArgumentParser(description="Multi-account idle resource audit.")
    ap.add_argument("--role-name", required=True, help="IAM role to assume in each account")
    ap.add_argument("--skip-accounts", default="AmanTest", help="Comma separated account names to skip")
    ap.add_argument("--stopped-days", type=int, default=30, help="Min days stopped before flagging EC2")
    ap.add_argument("--k8s-min-age-days", type=int, default=30, help="Min age for k8s volumes to show up")
    args = ap.parse_args()

    skip = {s.strip() for s in args.skip_accounts.split(",") if s.strip()}
    total_immediate = 0.0
    total_k8s = 0.0

    for acct_name, acct_id in ACCOUNTS.items():
        if acct_name in skip:
            continue

        print(f"\n=== {acct_name} ({acct_id}) ===")
        try:
            sess = assume_role(acct_id, args.role_name)
        except Exception as e:
            print(f"  couldn't assume role: {e}")
            continue

        acct_findings = []
        acct_k8s = []
        acct_cost = 0.0
        acct_k8s_cost = 0.0

        for region in enabled_regions(sess):
            c, kc, findings, k8s_findings = scan_region(
                sess, region, args.stopped_days, args.k8s_min_age_days,
            )
            acct_cost += c
            acct_k8s_cost += kc
            acct_findings.extend(findings)
            acct_k8s.extend(k8s_findings)

        if not acct_findings and not acct_k8s:
            print("  nothing found — £0.00/mo")
            continue

        if acct_findings:
            print("  Immediate cleanup:")
            for line in acct_findings:
                print(f"    {line}")

        if acct_k8s:
            print("  Needs K8s review first:")
            for line in acct_k8s:
                print(f"    {line}")

        print(f"  Est. savings: £{acct_cost:.2f}/mo immediate, £{acct_k8s_cost:.2f}/mo pending review")

        total_immediate += acct_cost
        total_k8s += acct_k8s_cost

    print(f"\n{'='*40}")
    print(f"TOTAL: £{total_immediate:.2f}/mo immediate + £{total_k8s:.2f}/mo k8s review = £{total_immediate + total_k8s:.2f}/mo")
    print(f"{'='*40}")


if __name__ == "__main__":
    main()
