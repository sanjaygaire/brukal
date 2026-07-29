"""
cloudscan.py — Cloud / infrastructure finding detector (AWS · Azure · GCP).

The cloud end. Deterministic signatures over the real output of cloud recon — both
HTTP-based (curl/wget against a bucket URL or an IMDS endpoint reached via SSRF) and
cloud-CLI (aws/az/gcloud, s3scanner, pacu). Catches the findings that actually matter:

  * public/listable object storage — S3, GCS, Azure Blob;
  * cloud metadata / IMDS exposed via SSRF (the classic pivot to instance credentials);
  * leaked cloud credentials — a GCP service-account JSON, an Azure storage key /
    connection string, live AWS credentials (an ARN from sts get-caller-identity);
  * an over-permissive IAM policy (Action:* / Resource:*) and privesc permissions;
  * an exposed Terraform state file; cloud provider fingerprints.

Deterministic pattern-matching over UNTRUSTED output — a hit becomes a governed FINDING
(evidence for the operator), never an action. No LLM here.
"""
from __future__ import annotations

import re

_CLOUD_SIGNALS = (
    # --- leaked credentials (critical) ----------------------------------------
    (re.compile(r'"type"\s*:\s*"service_account"[\s\S]{0,400}?"private_key"\s*:', re.I),
     "critical", "GCP service-account key exposed"),
    (re.compile(r'AccountName=[\w-]+;AccountKey=[A-Za-z0-9+/=]{40,}', ),
     "critical", "Azure storage account key / connection string exposed"),
    (re.compile(r'"AccessKeyId"\s*:\s*"ASIA[0-9A-Z]{16}"[\s\S]{0,200}?"Token"\s*:', re.I),
     "critical", "IMDS instance credentials exposed (SSRF → AWS role creds)"),
    (re.compile(r'"access_token"\s*:[\s\S]{0,120}?"token_type"\s*:\s*"Bearer"', re.I),
     "critical", "Cloud metadata OAuth token exposed (SSRF)"),
    # --- public storage (high) ------------------------------------------------
    (re.compile(r"<ListBucketResult\b[^>]*amazonaws", re.I), "high", "Public S3 bucket (listable)"),
    (re.compile(r"<ListBucketResult\b[^>]*(?:storage\.googleapis|googleapis\.com)", re.I),
     "high", "Public GCS bucket (listable)"),
    (re.compile(r"<EnumerationResults\b[^>]*(?:blob\.core\.windows\.net|ContainerName)", re.I),
     "high", "Public Azure blob container (listable)"),
    # --- live credentials / identity (high) -----------------------------------
    (re.compile(r"arn:aws:(?:iam|sts)::\d{12}:[\w/+=,.@-]+"), "high",
     "Valid AWS credentials (caller identity)"),
    (re.compile(r'"Effect"\s*:\s*"Allow"[\s\S]{0,120}?"Action"\s*:\s*"\*"[\s\S]{0,120}?'
                r'"Resource"\s*:\s*"\*"', re.I), "high",
     "Over-permissive IAM policy (Action:* Resource:*)"),
    (re.compile(r'"terraform_version"\s*:[\s\S]{0,200}?"resources"\s*:', re.I),
     "high", "Terraform state file exposed"),
    # --- privesc / recon (medium / info) --------------------------------------
    (re.compile(r"\b(?:iam:PassRole|iam:CreatePolicyVersion|iam:PutUserPolicy|"
                r"iam:AttachUserPolicy|iam:CreateAccessKey|sts:AssumeRole|"
                r"lambda:UpdateFunctionCode)\b"), "medium",
     "IAM privilege-escalation permission present"),
    (re.compile(r"169\.254\.169\.254|metadata\.google\.internal|"
                r"metadata\.azure\.com", re.I), "medium",
     "Cloud metadata endpoint reachable (SSRF surface)"),
    (re.compile(r"<Code>\s*AccessDenied\s*</Code>[\s\S]{0,80}?amazonaws", re.I),
     "info", "S3 bucket exists but is private (AccessDenied)"),
    (re.compile(r"(?i)Server:\s*AmazonS3|x-amz-request-id|x-ms-request-id|x-goog-generation"),
     "info", "Cloud provider fingerprint"),
)


def scan_cloud_output(text: str) -> list[tuple[str, str, str]]:
    """Scan cloud recon output (HTTP or CLI) for exposures and misconfig. Returns a list
    of (severity, label, evidence-line). Deterministic; flags for the operator."""
    hits: list[tuple[str, str, str]] = []
    seen: set = set()
    for rx, sev, label in _CLOUD_SIGNALS:
        m = rx.search(text or "")
        if m and label not in seen:
            seen.add(label)
            line = re.sub(r"\s+", " ", (m.group(0) or "")).strip()[:160]
            hits.append((sev, label, line))
    return hits


# Findings that are proof by construction (the tool reached/obtained it).
CONFIRMED_CLOUD_LABELS = frozenset({
    "GCP service-account key exposed", "Azure storage account key / connection string exposed",
    "IMDS instance credentials exposed (SSRF → AWS role creds)",
    "Cloud metadata OAuth token exposed (SSRF)", "Public S3 bucket (listable)",
    "Public GCS bucket (listable)", "Public Azure blob container (listable)",
    "Valid AWS credentials (caller identity)", "Terraform state file exposed",
})

# Tools whose output this detector understands (curl/wget included — cloud recon is
# heavily HTTP-based: bucket listings, IMDS via SSRF, fingerprinting).
CLOUD_TOOLS = frozenset({
    "aws", "az", "gcloud", "gsutil", "s3scanner", "s3cmd", "cloud_enum", "cloudenum",
    "pacu", "scoutsuite", "prowler", "nuclei", "curl", "wget",
})


def is_cloud_tool(command: str) -> bool:
    """True if the command's tool emits cloud recon output worth scanning."""
    import shlex
    try:
        toks = shlex.split(command)
    except ValueError:
        return False
    if not toks:
        return False
    return toks[0].rsplit("/", 1)[-1].lower() in CLOUD_TOOLS


METHODOLOGY = (
    "CLOUD / INFRASTRUCTURE METHODOLOGY (a cloud asset is in scope or discovered):\n"
    "1. Attribute: cloud fingerprints (Server: AmazonS3, x-amz/x-ms/x-goog headers), "
    "bucket URLs in JS/pages, cloud IPs/CNAMEs.\n"
    "2. Object storage: try to LIST anonymously — curl https://<bucket>.s3.amazonaws.com/ , "
    "https://storage.googleapis.com/<bucket>/ , https://<acct>.blob.core.windows.net/"
    "<container>?restype=container&comp=list ; a <ListBucketResult>/<EnumerationResults> "
    "= public. Then read objects.\n"
    "3. SSRF → IMDS: if an SSRF/redirect reaches 169.254.169.254 (AWS), "
    "metadata.google.internal (GCP), or 169.254.169.254/metadata (Azure), pull instance "
    "credentials / OAuth tokens.\n"
    "4. With credentials: aws sts get-caller-identity; enumerate what the key grants "
    "(s3/iam/lambda), look for privesc (iam:PassRole, CreatePolicyVersion, AssumeRole).\n"
    "5. Hunt leaked cloud secrets in code/JS/APK/git: GCP service-account JSON, Azure "
    "AccountKey/connection strings, AWS keys, exposed *.tfstate.\n"
    "Enumerate read-only first; anything that writes/creates resources ESCALATES for "
    "sign-off. One tool per step, only against authorised accounts/assets."
)
