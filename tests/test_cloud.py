"""
test_cloud.py — the Cloud / infrastructure detector (AWS · Azure · GCP).

Pins that cloudscan.scan_cloud_output turns real cloud recon output (HTTP bucket
listings, IMDS-via-SSRF responses, cloud-CLI output, leaked cloud secrets) into
findings, with no false positives on ordinary output; that a session records them as
cloud findings (definitive ones CONFIRMED); and that the cloud methodology surfaces to
the planner once a cloud asset is seen. Real output formats — no live cloud needed.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, cloudscan, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "scope.json"


def _labels(text):
    return [l for _s, l, _e in cloudscan.scan_cloud_output(text)]


def test_detects_public_storage_and_imds():
    assert "Public S3 bucket (listable)" in _labels(
        '<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        '<Name>corp-backups</Name><Contents><Key>db.sql</Key></Contents></ListBucketResult>')
    assert "Public Azure blob container (listable)" in _labels(
        '<EnumerationResults ContainerName="https://acct.blob.core.windows.net/data">'
        '<Blobs><Blob><Name>secret.txt</Name></Blob></Blobs></EnumerationResults>')
    imds = ('{ "Code" : "Success", "AccessKeyId" : "ASIAABCDEFGHIJKLMNOP", '
            '"SecretAccessKey" : "x", "Token" : "FwoGZ..." }')
    assert "IMDS instance credentials exposed (SSRF → AWS role creds)" in _labels(imds)


def test_detects_leaked_cloud_secrets():
    gcp = '{ "type": "service_account", "project_id": "p", "private_key": "-----BEGIN..." }'
    assert "GCP service-account key exposed" in _labels(gcp)
    az = "DefaultEndpointsProtocol=https;AccountName=corpstore;AccountKey=" + "A" * 44 + "==;"
    assert "Azure storage account key / connection string exposed" in _labels(az)


def test_detects_identity_iam_and_tfstate():
    assert "Valid AWS credentials (caller identity)" in _labels(
        '{ "UserId": "AID", "Account": "123456789012", '
        '"Arn": "arn:aws:iam::123456789012:user/deploy" }')
    pol = '{ "Effect": "Allow", "Action": "*", "Resource": "*" }'
    assert "Over-permissive IAM policy (Action:* Resource:*)" in _labels(pol)
    assert "Terraform state file exposed" in _labels(
        '{ "version": 4, "terraform_version": "1.5.0", "resources": [ {"type":"aws_db"} ] }')
    assert "IAM privilege-escalation permission present" in _labels(
        '{ "Action": ["iam:PassRole", "sts:AssumeRole"] }')


def test_no_false_positive_on_ordinary_output():
    assert cloudscan.scan_cloud_output("HTTP/1.1 200 OK\n<html>welcome to the shop</html>") == []
    assert cloudscan.scan_cloud_output("nmap scan report: 3 ports open") == []


def test_is_cloud_tool():
    assert cloudscan.is_cloud_tool("aws s3 ls s3://corp-backups --no-sign-request")
    assert cloudscan.is_cloud_tool("curl https://corp.s3.amazonaws.com/")
    assert not cloudscan.is_cloud_tool("nmap -sV 10.10.10.5")


def _session():
    scope = load_scope(FIXTURE)
    ex = Executor(Gate(scope), FakeKali(), AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl"))
    return AssistSession("10.10.10.5", ex, StrategistAgent(
        type("L", (), {"propose": lambda *a, **k: ""})()))


def test_session_records_confirmed_cloud_finding():
    sess = _session()
    for sev, label, line in cloudscan.scan_cloud_output(
            '<ListBucketResult xmlns="http://s3.amazonaws.com/">...</ListBucketResult>'):
        sess._record_cloud_finding("curl https://corp-backups.s3.amazonaws.com/", sev, label, line)
    f = next(f for f in sess.findings.all() if f.title == "Public S3 bucket (listable)")
    assert f.confirmed is True and f.category == "cloud"


def test_cloud_methodology_surfaces_when_cloud_detected():
    sess = _session()
    assert "CLOUD / INFRASTRUCTURE" not in sess._reference("")
    sess.highlights.append(("hdr", "Server: AmazonS3 x-amz-request-id: ABC"))
    assert "CLOUD / INFRASTRUCTURE" in sess._reference("")
