#!/usr/bin/env python3
"""
Populates floci with a small, believable set of resources on startup.
floci's storage is in-memory -- every restart comes back completely
empty across every service, which is itself a tell: a real
compromised AWS account almost never looks this blank. This creates
just enough to read as a genuine (if modest) ML training environment,
consistent with the ray-ml-training-role bait already planted via
IMDS -- not an exhaustive inventory, just enough that basic
enumeration (describe-instances, list-buckets, list-roles,
list-tables) doesn't come back empty.

Hits floci directly at 127.0.0.2:4566, bypassing envoy entirely --
this is our own setup traffic, not an attacker's, and it shouldn't
show up in the CloudTrail-shaped log or trigger a Discord alert.

Stdlib only, no pip install: this container shares the same network
namespace as everything else, so any real outbound HTTPS -- including
`pip install`'s own connection to PyPI -- gets caught by the same
443 redirect and MITM'd by our own fake *.amazonaws.com cert, which
PyPI's real hostname obviously doesn't match. Rather than carve out
an iptables exemption for PyPI's CDN (fragile, IPs change), this just
doesn't need any external package at all.

floci parses the Authorization header's Credential=.../<service>/...
scope to route requests but doesn't validate the signature
cryptographically (confirmed repeatedly against the live cluster --
a garbage signature routes and executes fine), so these requests
don't bother with real SigV4 math, just the correctly-shaped header
floci's router expects.

EC2 instances are seeded on a real best-effort basis but floci
auto-transitions every RunInstances result straight to `terminated`
within a few seconds regardless of parameters (confirmed: happens for
any AMI ID, and terminated instances can't be un-terminated via
StartInstances either, matching real AWS's own irreversible-
termination rule) -- something floci itself controls, not this
script. describe_instances still shows full, realistic detail (AMI,
type, tags, VPC, termination time) rather than an empty list, which
is the actual gap this closes; it just won't read as a currently-
running fleet.

Runs once, then sleeps forever -- if this exited cleanly, the
container orchestrator would restart it (Kubernetes' default
restartPolicy, Compose's own restart handling), re-running every
create call and piling up duplicate EC2 instances each time.
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

ENDPOINT = "http://127.0.0.2:4566/"
REGION = "us-east-1"


def auth_header(service):
    return (
        f"AWS4-HMAC-SHA256 Credential=AKIASEEDSEEDSEEDSEED/20260101/"
        f"{REGION}/{service}/aws4_request, SignedHeaders=host, Signature=seed"
    )


def call(service, host, headers, body, method="POST", path=""):
    req_headers = {"Host": host, "Authorization": auth_header(service), **headers}
    req = urllib.request.Request(ENDPOINT + path, data=body.encode(), headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def wait_for_floci():
    for attempt in range(30):
        try:
            status, _ = call("ec2", "ec2.amazonaws.com", {"Content-Type": "application/x-www-form-urlencoded"},
                              "Action=DescribeVpcs&Version=2016-11-15")
            print(f"floci is up (status {status})", flush=True)
            return
        except Exception as e:
            print(f"waiting for floci ({attempt + 1}/30): {e}", flush=True)
            time.sleep(2)
    raise RuntimeError("floci never became reachable")


def run_instance(name):
    body = urllib.parse.urlencode({
        "Action": "RunInstances",
        "Version": "2016-11-15",
        "ImageId": "ami-0c55b159cbfafe1f0",
        "InstanceType": "g5.2xlarge",
        "MinCount": "1",
        "MaxCount": "1",
        "TagSpecification.1.ResourceType": "instance",
        "TagSpecification.1.Tag.1.Key": "Name",
        "TagSpecification.1.Tag.1.Value": name,
    })
    status, resp = call("ec2", "ec2.amazonaws.com",
                         {"Content-Type": "application/x-www-form-urlencoded"}, body)
    print(f"RunInstances {name}: {status}", flush=True)


def create_bucket(bucket):
    # Path-style, not virtual-hosted-style: PUT /bucket against
    # Host: s3.amazonaws.com is what floci's router actually expects
    # -- confirmed against the live stack, virtual-hosted-style
    # (Host: bucket.s3.amazonaws.com) returned 405.
    status, resp = call("s3", "s3.amazonaws.com", {}, "", method="PUT", path=bucket)
    print(f"CreateBucket {bucket}: {status}", flush=True)


def create_role(role_name):
    trust_policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    body = urllib.parse.urlencode({
        "Action": "CreateRole",
        "Version": "2010-05-08",
        "RoleName": role_name,
        "AssumeRolePolicyDocument": trust_policy,
    })
    status, resp = call("iam", "iam.amazonaws.com",
                         {"Content-Type": "application/x-www-form-urlencoded"}, body)
    print(f"CreateRole {role_name}: {status}", flush=True)


def create_table(table_name):
    body = json.dumps({
        "TableName": table_name,
        "KeySchema": [{"AttributeName": "experiment_id", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "experiment_id", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
    })
    status, resp = call("dynamodb", "dynamodb.us-east-1.amazonaws.com", {
        "Content-Type": "application/x-amz-json-1.0",
        "X-Amz-Target": "DynamoDB_20120810.CreateTable",
    }, body)
    print(f"CreateTable {table_name}: {status}", flush=True)


def seed():
    print("seeding EC2 instances...", flush=True)
    for name in ["ray-head-node", "ray-worker-node-1", "ray-worker-node-2"]:
        run_instance(name)

    print("seeding S3 buckets...", flush=True)
    for bucket in ["ml-training-datasets-prod", "ml-model-checkpoints", "ray-cluster-logs"]:
        create_bucket(bucket)

    print("seeding IAM roles...", flush=True)
    # Matches the role name the IMDS bait already hands back -- listing
    # IAM roles and querying instance metadata should tell the same story.
    for role in ["ray-ml-training-role-vpce-restricted", "s3-data-access-role"]:
        create_role(role)

    print("seeding DynamoDB table...", flush=True)
    create_table("ml-experiment-metadata")

    print("seeding done", flush=True)


if __name__ == "__main__":
    wait_for_floci()
    seed()
    while True:
        time.sleep(3600)
