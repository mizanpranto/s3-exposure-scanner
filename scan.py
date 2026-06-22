"""
S3 Exposure Scanner
====================
Cloud Security Consultant Tool
Scans all S3 buckets in an AWS account across 10 security checks.
Outputs a professional PDF report for client delivery.

Usage: python scan.py
"""

import json
import sys
from datetime import date, datetime

# ── PDF ──────────────────────────────────────────────────────────────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.pdfgen import canvas

# ─────────────────────────────────────────────────────────────────────────────
# BRAND COLORS  (matches assessment report suite)
# ─────────────────────────────────────────────────────────────────────────────
DARK        = colors.HexColor("#0D1117")
DARK2       = colors.HexColor("#161B22")
GREEN       = colors.HexColor("#1D9E75")
GREEN_LIGHT = colors.HexColor("#E1F5EE")
BLUE        = colors.HexColor("#185FA5")
BLUE_LIGHT  = colors.HexColor("#E3EEF9")
RED         = colors.HexColor("#C0392B")
RED_LIGHT   = colors.HexColor("#FCEBEB")
ORANGE      = colors.HexColor("#E67E22")
ORANGE_LIGHT= colors.HexColor("#FAEEDA")
GRAY        = colors.HexColor("#6E7681")
GRAY_LIGHT  = colors.HexColor("#F6F8FA")
WHITE       = colors.white

W_PAGE, H_PAGE = A4
MARGIN      = 14 * mm
CONTENT_W   = W_PAGE - 2 * MARGIN

# ─────────────────────────────────────────────────────────────────────────────
# STYLES
# ─────────────────────────────────────────────────────────────────────────────
def S(name, **kw):
    defaults = dict(fontName="Helvetica", fontSize=9.5,
                    textColor=colors.HexColor("#24292F"), leading=14)
    defaults.update(kw)
    return ParagraphStyle(name, **defaults)

STYLES = {
    "cover_title":   S("ct",  fontName="Helvetica-Bold", fontSize=26, textColor=WHITE, leading=32),
    "cover_sub":     S("cs",  fontSize=13, textColor=colors.HexColor("#9FE1CB"), leading=18),
    "cover_meta":    S("cm",  fontSize=10, textColor=colors.HexColor("#8B949E"), leading=14),
    "cover_warn":    S("cw",  fontName="Helvetica-Bold", fontSize=9, textColor=ORANGE, leading=12),
    "section":       S("sh",  fontName="Helvetica-Bold", fontSize=14, textColor=DARK,
                              spaceBefore=18, spaceAfter=10, leading=18),
    "sub":           S("sbh", fontName="Helvetica-Bold", fontSize=11, textColor=DARK,
                              spaceBefore=10, spaceAfter=4, leading=14),
    "body":          S("b",   fontSize=9.5, leading=14, spaceAfter=4),
    "small":         S("sm",  fontSize=8.5, textColor=GRAY, leading=12),
    "label":         S("lb",  fontName="Helvetica-Bold", fontSize=8, textColor=GRAY, leading=11),
    "mono":          S("mo",  fontName="Courier", fontSize=8.5, textColor=DARK, leading=12),
    "toc":           S("tc",  fontSize=10, textColor=BLUE, leading=16, leftIndent=10),
    "pass":          S("ps",  fontName="Helvetica-Bold", fontSize=8, textColor=GREEN, alignment=TA_CENTER),
    "fail":          S("fl",  fontName="Helvetica-Bold", fontSize=8, textColor=RED,   alignment=TA_CENTER),
    "na":            S("na",  fontName="Helvetica-Bold", fontSize=8, textColor=GRAY,  alignment=TA_CENTER),
}

SEV_COLORS = {
    "CRITICAL": (RED,    RED_LIGHT,    colors.HexColor("#C0392B")),
    "HIGH":     (ORANGE, ORANGE_LIGHT, colors.HexColor("#E67E22")),
    "MEDIUM":   (BLUE,   BLUE_LIGHT,   colors.HexColor("#185FA5")),
    "LOW":      (GREEN,  GREEN_LIGHT,  colors.HexColor("#1D9E75")),
}

# ─────────────────────────────────────────────────────────────────────────────
# CHECK DEFINITIONS  — 10 checks mapped to compliance / client pain
# ─────────────────────────────────────────────────────────────────────────────
CHECKS = [
    {
        "id":          "S3-001",
        "name":        "Block Public Access Disabled",
        "severity":    "CRITICAL",
        "category":    "Public Access",
        "description": "The account-level or bucket-level S3 Block Public Access setting is not fully enabled. This safety net prevents accidental public exposure from any ACL or bucket policy change.",
        "impact":      "A single misconfigured ACL or bucket policy can expose data to the entire internet with no account-level guardrail to prevent it.",
        "fix":         "Enable all 4 Block Public Access settings at the account level in S3 > Block Public Access. Also enable at the bucket level for each bucket.",
        "reference":   "AWS CIS Benchmark v1.5 — Control 2.1.5 | PCI-DSS Requirement 1.3",
    },
    {
        "id":          "S3-002",
        "name":        "Bucket Publicly Accessible via ACL",
        "severity":    "CRITICAL",
        "category":    "Public Access",
        "description": "The bucket has a legacy ACL granting READ, WRITE, or FULL_CONTROL to AllUsers or AuthenticatedUsers groups, making objects accessible without authentication.",
        "impact":      "Customer data, backups, and application files are exposed to the entire public internet. Direct GDPR Article 32 and PCI-DSS Requirement 3 violation.",
        "fix":         "Remove all public ACL grants. Switch to bucket policies for access control. Enable Block Public Access to prevent ACL-based public access.",
        "reference":   "AWS CIS Benchmark v1.5 — Control 2.1.5 | GDPR Article 32",
    },
    {
        "id":          "S3-003",
        "name":        "Bucket Publicly Accessible via Policy",
        "severity":    "CRITICAL",
        "category":    "Public Access",
        "description": "The bucket policy contains a statement with Principal: '*' and no restrictive conditions, allowing any unauthenticated request to access bucket objects.",
        "impact":      "Public read or write access to bucket objects without any authentication. More dangerous than ACL exposure as policies can grant write access to anonymous users.",
        "fix":         "Review and remove all Principal: '*' statements. If public access is intentional (e.g. static website), restrict to specific actions (s3:GetObject only) and enable CloudFront instead.",
        "reference":   "AWS CIS Benchmark v1.5 — Control 2.1.5 | OWASP Cloud Security",
    },
    {
        "id":          "S3-004",
        "name":        "No Default Encryption",
        "severity":    "HIGH",
        "category":    "Encryption",
        "description": "The bucket does not have default server-side encryption configured. Objects uploaded without explicit encryption headers are stored in plaintext.",
        "impact":      "Data at rest is unencrypted. Violates PCI-DSS Requirement 3.4 (protect stored cardholder data) and GDPR Article 32 (appropriate technical measures). Required for SOC 2 CC6.1.",
        "fix":         "Enable default SSE-S3 encryption on the bucket (zero cost, zero performance impact). For sensitive data, use SSE-KMS with a Customer Managed Key for full audit trail.",
        "reference":   "AWS CIS Benchmark v1.5 — Control 2.1.1 | PCI-DSS Requirement 3.4 | SOC 2 CC6.1",
    },
    {
        "id":          "S3-005",
        "name":        "HTTP Access Allowed (No HTTPS Enforcement)",
        "severity":    "HIGH",
        "category":    "Encryption",
        "description": "The bucket policy does not contain a condition denying requests made over HTTP (aws:SecureTransport: false). Objects can be accessed over unencrypted HTTP connections.",
        "impact":      "Data in transit is unencrypted and vulnerable to man-in-the-middle interception. Violates PCI-DSS Requirement 4.1 (encrypt transmission of cardholder data).",
        "fix":         'Add a bucket policy statement with Condition: {"Bool": {"aws:SecureTransport": "false"}} and Effect: Deny to enforce HTTPS-only access.',
        "reference":   "AWS CIS Benchmark v1.5 — Control 2.1.2 | PCI-DSS Requirement 4.1",
    },
    {
        "id":          "S3-006",
        "name":        "Server Access Logging Disabled",
        "severity":    "HIGH",
        "category":    "Logging",
        "description": "S3 server access logging is not enabled for this bucket. There is no record of who accessed, downloaded, modified, or deleted objects in this bucket.",
        "impact":      "Inability to detect data exfiltration, investigate breaches, or satisfy forensic requirements. Required for ISO 27001 A.12.4 and SOC 2 CC7.2 audit logging controls.",
        "fix":         "Enable server access logging and route logs to a dedicated, write-only logging bucket. Set a minimum 90-day log retention policy. Consider Amazon Macie for sensitive data detection.",
        "reference":   "AWS CIS Benchmark v1.5 — Control 2.1.3 | ISO 27001 A.12.4 | PCI-DSS Requirement 10",
    },
    {
        "id":          "S3-007",
        "name":        "Versioning Disabled",
        "severity":    "HIGH",
        "category":    "Resilience",
        "description": "S3 versioning is not enabled. When versioning is off, overwritten or deleted objects are permanently gone with no ability to recover previous versions.",
        "impact":      "Ransomware attacks that overwrite or delete objects result in permanent, unrecoverable data loss. No protection against accidental deletions or application bugs that corrupt data.",
        "fix":         "Enable S3 versioning on all buckets containing important data. Combine with lifecycle rules to expire old versions after 30-90 days to manage storage costs.",
        "reference":   "AWS Best Practices | NIST SP 800-53 CP-9 | ISO 27001 A.12.3",
    },
    {
        "id":          "S3-008",
        "name":        "MFA Delete Disabled",
        "severity":    "HIGH",
        "category":    "Resilience",
        "description": "MFA Delete is not enabled on this bucket. Without MFA Delete, any compromised IAM credential with s3:DeleteObject permission can permanently delete versioned objects.",
        "impact":      "A compromised IAM key can irreversibly delete all versions of all objects in the bucket. No recovery possible after permanent deletion without MFA requirement.",
        "fix":         "Enable MFA Delete using the root account credentials and a hardware MFA device. This requires presenting MFA for any versioned object deletion operation.",
        "reference":   "AWS S3 Security Best Practices | PCI-DSS Requirement 8.3",
    },
    {
        "id":          "S3-009",
        "name":        "Cross-Account Access in Bucket Policy",
        "severity":    "MEDIUM",
        "category":    "Access Control",
        "description": "The bucket policy grants access to IAM principals from external AWS account IDs. This means third parties outside your AWS organization can access this bucket.",
        "impact":      "Supply chain risk — if the third-party AWS account is compromised, the attacker gains access to your bucket. Unauthorised cross-account access is a common data breach vector.",
        "fix":         "Audit all cross-account principals in the bucket policy. Remove any that are no longer needed. For required third-party access, use AWS RAM or pre-signed URLs with expiry instead.",
        "reference":   "AWS S3 Security Best Practices | ISO 27001 A.15 (Supplier Relationships)",
    },
    {
        "id":          "S3-010",
        "name":        "No Lifecycle Policy Configured",
        "severity":    "MEDIUM",
        "category":    "Data Governance",
        "description": "No S3 lifecycle policy is configured for this bucket. Objects are retained indefinitely with no automated tiering, archival, or deletion of old data.",
        "impact":      "Old and unnecessary data accumulates indefinitely, increasing storage costs and the potential blast radius of a breach. Uncontrolled data retention may violate GDPR data minimisation principles.",
        "fix":         "Create an S3 lifecycle policy to: transition objects to S3-IA after 30 days, Glacier after 90 days, and delete after your data retention policy period (e.g. 1 or 7 years).",
        "reference":   "GDPR Article 5(1)(e) — Storage Limitation | ISO 27001 A.8.3 | AWS Cost Optimisation",
    },
]

CHECK_MAP = {c["id"]: c for c in CHECKS}

# ─────────────────────────────────────────────────────────────────────────────
# TERMINAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def clr(text, code): return f"\033[{code}m{text}\033[0m"
def green(t):  return clr(t, "32")
def red(t):    return clr(t, "31")
def yellow(t): return clr(t, "33")
def bold(t):   return clr(t, "1")
def dim(t):    return clr(t, "2")

def banner():
    print("\n")
    print(bold("╔══════════════════════════════════════════════════════════╗"))
    print(bold("║        S3 EXPOSURE SCANNER                              ║"))
    print(bold("║        Cloud Security Consultant Tool                   ║"))
    print(bold("╚══════════════════════════════════════════════════════════╝"))
    print(dim("  Scans all S3 buckets · 10 security checks · PDF report\n"))

def sep(title=""):
    print("\n" + "─" * 60)
    if title:
        print(f"  {bold(title)}")
        print("─" * 60)

def ask(label, default=None, secret=False):
    hint = f" [{default}]" if default else ""
    while True:
        if secret:
            import getpass
            val = getpass.getpass(f"  {label}{hint}: ").strip()
        else:
            val = input(f"  {label}{hint}: ").strip()
        if val:
            return val
        if default is not None:
            return default
        print(red("  ⚠  Required field."))

def spinner_msg(msg):
    print(f"  ⏳ {msg}", end="\r")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — COLLECT CREDENTIALS & CLIENT INFO
# ─────────────────────────────────────────────────────────────────────────────
def collect_inputs():
    banner()

    sep("STEP 1 of 3 — YOUR CONSULTANT DETAILS")
    consultant = {
        "name":  ask("Your full name",  default="Your Name"),
        "title": ask("Your title",       default="Cloud Security Consultant"),
        "email": ask("Your email",       default="hello@yoursite.com"),
        "certs": ask("Your certifications", default="AWS SAA Certified | ISO 27001 | NIST | GDPR"),
    }

    sep("STEP 2 of 3 — CLIENT DETAILS")
    client = {
        "name":     ask("Client company name"),
        "industry": ask("Client industry",     default="SaaS"),
        "contact":  ask("Client contact name", default="CTO"),
    }

    sep("STEP 3 of 3 — AWS CREDENTIALS")
    print(dim("  (Read-only credentials — scanner never writes to your AWS account)\n"))
    print(dim("  Required IAM permissions:"))
    print(dim("  s3:ListAllMyBuckets, s3:GetBucketAcl, s3:GetBucketPolicy,"))
    print(dim("  s3:GetBucketEncryption, s3:GetBucketLogging, s3:GetBucketVersioning,"))
    print(dim("  s3:GetBucketLifecycleConfiguration, s3:GetBucketPublicAccessBlock\n"))

    creds = {
        "access_key":    ask("AWS Access Key ID",         secret=True),
        "secret_key":    ask("AWS Secret Access Key",     secret=True),
        "session_token": ask("AWS Session Token (optional — press Enter to skip)", default=""),
        "region":        ask("Default region", default="us-east-1"),
        "account_id":    ask("AWS Account ID (12 digits)"),
    }

    safe_name   = client["name"].lower().replace(" ", "_").replace(".", "").replace(",", "")
    default_out = f"s3_scan_{safe_name}_{date.today().strftime('%Y%m%d')}.pdf"
    output_path = ask("Output PDF filename", default=default_out)
    if not output_path.endswith(".pdf"):
        output_path += ".pdf"

    return consultant, client, creds, output_path

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — RUN SCANS
# ─────────────────────────────────────────────────────────────────────────────
def connect_aws(creds):
    try:
        import boto3
        kwargs = dict(
            aws_access_key_id     = creds["access_key"],
            aws_secret_access_key = creds["secret_key"],
            region_name           = creds["region"],
        )
        if creds["session_token"]:
            kwargs["aws_session_token"] = creds["session_token"]
        session = boto3.Session(**kwargs)
        s3      = session.client("s3")
        return s3
    except ImportError:
        print(red("\n  ✗ boto3 not installed. Run: pip install boto3"))
        sys.exit(1)
    except Exception as e:
        print(red(f"\n  ✗ AWS connection failed: {e}"))
        sys.exit(1)

def list_buckets(s3):
    try:
        resp    = s3.list_buckets()
        buckets = resp.get("Buckets", [])
        return [b["Name"] for b in buckets]
    except Exception as e:
        print(red(f"\n  ✗ Could not list buckets: {e}"))
        sys.exit(1)

def safe_get(fn, *args, **kwargs):
    """Call a boto3 method safely — returns (result, error_string)."""
    try:
        return fn(*args, **kwargs), None
    except Exception as e:
        return None, str(e)

def check_bucket(s3, bucket_name):
    """
    Run all 10 checks on a single bucket.
    Returns dict: { check_id: "PASS" | "FAIL" | "ERROR", detail: str }
    """
    results = {}

    # ── S3-001: Block Public Access ──────────────────────────────────────────
    bpa, err = safe_get(s3.get_bucket_public_access_block, Bucket=bucket_name)
    if err:
        results["S3-001"] = {"status": "FAIL", "detail": "Block Public Access config not found — treated as disabled."}
    else:
        cfg   = bpa.get("PublicAccessBlockConfiguration", {})
        all_on = all([
            cfg.get("BlockPublicAcls",       False),
            cfg.get("IgnorePublicAcls",      False),
            cfg.get("BlockPublicPolicy",     False),
            cfg.get("RestrictPublicBuckets", False),
        ])
        results["S3-001"] = {
            "status": "PASS" if all_on else "FAIL",
            "detail": "All 4 Block Public Access settings enabled." if all_on
                      else f"Settings: BlockPublicAcls={cfg.get('BlockPublicAcls',False)}, "
                           f"IgnorePublicAcls={cfg.get('IgnorePublicAcls',False)}, "
                           f"BlockPublicPolicy={cfg.get('BlockPublicPolicy',False)}, "
                           f"RestrictPublicBuckets={cfg.get('RestrictPublicBuckets',False)}",
        }

    # ── S3-002: Public ACL ───────────────────────────────────────────────────
    acl, err = safe_get(s3.get_bucket_acl, Bucket=bucket_name)
    if err:
        results["S3-002"] = {"status": "ERROR", "detail": f"Could not retrieve ACL: {err}"}
    else:
        public_grants = []
        PUBLIC_URIS   = [
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        ]
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("URI") in PUBLIC_URIS:
                public_grants.append(f"{grantee.get('URI','').split('/')[-1]} → {grant.get('Permission','')}")
        results["S3-002"] = {
            "status": "FAIL" if public_grants else "PASS",
            "detail": f"Public ACL grants found: {'; '.join(public_grants)}" if public_grants
                      else "No public ACL grants detected.",
        }

    # ── S3-003: Public Policy ────────────────────────────────────────────────
    pol, err = safe_get(s3.get_bucket_policy, Bucket=bucket_name)
    if err:
        # NoSuchBucketPolicy = no policy = PASS
        if "NoSuchBucketPolicy" in str(err):
            results["S3-003"] = {"status": "PASS", "detail": "No bucket policy configured."}
        else:
            results["S3-003"] = {"status": "ERROR", "detail": f"Could not retrieve policy: {err}"}
    else:
        try:
            policy_doc  = json.loads(pol["Policy"])
            public_stmts = []
            for stmt in policy_doc.get("Statement", []):
                principal = stmt.get("Principal", "")
                effect    = stmt.get("Effect", "")
                if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                    condition = stmt.get("Condition", {})
                    if not condition:
                        public_stmts.append(f"Action: {stmt.get('Action','*')}")
            results["S3-003"] = {
                "status": "FAIL" if public_stmts else "PASS",
                "detail": f"Public policy statements: {'; '.join(public_stmts)}" if public_stmts
                          else "No unrestricted Principal: * statements found.",
            }
        except Exception:
            results["S3-003"] = {"status": "ERROR", "detail": "Could not parse bucket policy JSON."}

    # ── S3-004: Encryption ───────────────────────────────────────────────────
    enc, err = safe_get(s3.get_bucket_encryption, Bucket=bucket_name)
    if err:
        if "ServerSideEncryptionConfigurationNotFoundError" in str(err):
            results["S3-004"] = {"status": "FAIL", "detail": "No default encryption configured. Objects stored in plaintext."}
        else:
            results["S3-004"] = {"status": "ERROR", "detail": f"Could not check encryption: {err}"}
    else:
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            rule    = rules[0]
            algo    = rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "?")
            kms_key = rule.get("ApplyServerSideEncryptionByDefault", {}).get("KMSMasterKeyID", "")
            detail  = f"Encryption: {algo}"
            if kms_key:
                detail += f" with KMS key: ...{kms_key[-12:]}"
            results["S3-004"] = {"status": "PASS", "detail": detail}
        else:
            results["S3-004"] = {"status": "FAIL", "detail": "Encryption rules list is empty."}

    # ── S3-005: HTTPS enforcement ────────────────────────────────────────────
    if pol and "Policy" in pol:
        try:
            policy_doc = json.loads(pol["Policy"])
            https_deny = False
            for stmt in policy_doc.get("Statement", []):
                cond = stmt.get("Condition", {})
                if (stmt.get("Effect") == "Deny" and
                        cond.get("Bool", {}).get("aws:SecureTransport") in ["false", False]):
                    https_deny = True
                    break
            results["S3-005"] = {
                "status": "PASS" if https_deny else "FAIL",
                "detail": "Bucket policy enforces HTTPS-only (aws:SecureTransport deny rule found)." if https_deny
                          else "No HTTPS-enforcement deny rule in bucket policy. HTTP access is allowed.",
            }
        except Exception:
            results["S3-005"] = {"status": "ERROR", "detail": "Could not parse policy for HTTPS check."}
    else:
        results["S3-005"] = {"status": "FAIL", "detail": "No bucket policy — HTTP access is allowed by default."}

    # ── S3-006: Access Logging ───────────────────────────────────────────────
    log, err = safe_get(s3.get_bucket_logging, Bucket=bucket_name)
    if err:
        results["S3-006"] = {"status": "ERROR", "detail": f"Could not check logging: {err}"}
    else:
        logging_enabled = bool(log.get("LoggingEnabled"))
        if logging_enabled:
            target = log["LoggingEnabled"].get("TargetBucket", "unknown")
            prefix = log["LoggingEnabled"].get("TargetPrefix", "")
            results["S3-006"] = {"status": "PASS", "detail": f"Logging → s3://{target}/{prefix}"}
        else:
            results["S3-006"] = {"status": "FAIL", "detail": "Server access logging is disabled."}

    # ── S3-007: Versioning ───────────────────────────────────────────────────
    ver, err = safe_get(s3.get_bucket_versioning, Bucket=bucket_name)
    if err:
        results["S3-007"] = {"status": "ERROR", "detail": f"Could not check versioning: {err}"}
    else:
        status = ver.get("Status", "")
        results["S3-007"] = {
            "status": "PASS" if status == "Enabled" else "FAIL",
            "detail": f"Versioning: {status or 'Never enabled'}",
        }

    # ── S3-008: MFA Delete ───────────────────────────────────────────────────
    if ver is not None:
        mfa_delete = ver.get("MFADelete", "")
        results["S3-008"] = {
            "status": "PASS" if mfa_delete == "Enabled" else "FAIL",
            "detail": f"MFA Delete: {mfa_delete or 'Disabled'}",
        }
    else:
        results["S3-008"] = {"status": "ERROR", "detail": "Could not retrieve versioning config for MFA Delete check."}

    # ── S3-009: Cross-Account Access ─────────────────────────────────────────
    own_account = ""  # We'll check for foreign account IDs in policy
    cross_accounts = []
    if pol and "Policy" in pol:
        try:
            policy_doc  = json.loads(pol["Policy"])
            for stmt in policy_doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal", {})
                aws_principals = []
                if isinstance(principal, str) and principal != "*":
                    aws_principals = [principal]
                elif isinstance(principal, dict):
                    val = principal.get("AWS", [])
                    aws_principals = [val] if isinstance(val, str) else val
                for p in aws_principals:
                    if "arn:aws:iam::" in p:
                        acct = p.split(":")[4]
                        if acct and acct not in cross_accounts:
                            cross_accounts.append(acct)
        except Exception:
            pass
    results["S3-009"] = {
        "status": "FAIL" if cross_accounts else "PASS",
        "detail": f"Cross-account access granted to account(s): {', '.join(cross_accounts)}" if cross_accounts
                  else "No cross-account principals detected in bucket policy.",
    }

    # ── S3-010: Lifecycle Policy ─────────────────────────────────────────────
    lc, err = safe_get(s3.get_bucket_lifecycle_configuration, Bucket=bucket_name)
    if err:
        if "NoSuchLifecycleConfiguration" in str(err):
            results["S3-010"] = {"status": "FAIL", "detail": "No lifecycle policy configured. Objects retained indefinitely."}
        else:
            results["S3-010"] = {"status": "ERROR", "detail": f"Could not check lifecycle: {err}"}
    else:
        rules = lc.get("Rules", [])
        enabled = [r for r in rules if r.get("Status") == "Enabled"]
        results["S3-010"] = {
            "status": "PASS" if enabled else "FAIL",
            "detail": f"{len(enabled)} active lifecycle rule(s) configured." if enabled
                      else "Lifecycle rules exist but none are enabled.",
        }

    return results

def scan_all_buckets(s3, bucket_names):
    sep("SCANNING BUCKETS")
    all_results = {}
    total = len(bucket_names)

    for i, name in enumerate(bucket_names, 1):
        print(f"  [{i:>2}/{total}]  {name:<55}", end="\r")
        all_results[name] = check_bucket(s3, name)

    print(" " * 70, end="\r")  # clear line
    print(f"  {green('✓')} Scanned {total} bucket(s) across 10 checks.\n")
    return all_results

def build_findings(all_results):
    """Convert raw results into list of Finding dicts for the PDF."""
    findings = []
    for bucket_name, checks in all_results.items():
        for check_id, result in checks.items():
            if result["status"] == "FAIL":
                check = CHECK_MAP[check_id]
                findings.append({
                    "bucket":      bucket_name,
                    "check_id":    check_id,
                    "check_name":  check["name"],
                    "severity":    check["severity"],
                    "category":    check["category"],
                    "description": check["description"],
                    "detail":      result["detail"],
                    "impact":      check["impact"],
                    "fix":         check["fix"],
                    "reference":   check["reference"],
                })
    # Sort: CRITICAL first, then HIGH, MEDIUM, LOW
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f["bucket"]))
    return findings

def calc_score(all_results):
    counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    weights = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}
    for bucket_checks in all_results.values():
        for check_id, result in bucket_checks.items():
            if result["status"] == "FAIL":
                sev = CHECK_MAP[check_id]["severity"]
                counts[sev] += 1
    total    = sum(counts.values())
    deduct   = sum(counts[s] * weights[s] for s in counts)
    score    = max(0, 100 - deduct)
    rating   = ("GOOD" if score >= 80 else
                "FAIR" if score >= 60 else
                "NEEDS IMPROVEMENT" if score >= 40 else
                "CRITICAL RISK")
    return counts, total, score, rating

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — GENERATE PDF REPORT
# ─────────────────────────────────────────────────────────────────────────────
class ScanCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        self._meta = kwargs.pop("meta", {})
        self._pages = []
        super().__init__(*args, **kwargs)

    def showPage(self):
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._pages)
        for n, page in enumerate(self._pages, 1):
            self.__dict__.update(page)
            if n > 1:
                self._draw_chrome(n, total)
            super().showPage()
        super().save()

    def _draw_chrome(self, n, total):
        m = self._meta
        # Header
        self.setFillColor(DARK)
        self.rect(0, H_PAGE - 22*mm, W_PAGE, 22*mm, fill=1, stroke=0)
        self.setFillColor(GREEN)
        self.rect(0, H_PAGE - 22*mm, 4, 22*mm, fill=1, stroke=0)
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(WHITE)
        self.drawString(14*mm, H_PAGE - 13*mm, "S3 EXPOSURE SCAN REPORT")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#8B949E"))
        self.drawRightString(W_PAGE - 14*mm, H_PAGE - 13*mm,
                             f"{m.get('client_name','')}  ·  CONFIDENTIAL")
        # Footer
        self.setFillColor(GRAY_LIGHT)
        self.rect(0, 0, W_PAGE, 12*mm, fill=1, stroke=0)
        self.setFillColor(GREEN)
        self.rect(0, 0, W_PAGE, 1, fill=1, stroke=0)
        self.setFont("Helvetica", 7)
        self.setFillColor(GRAY)
        self.drawString(14*mm, 4*mm,
            f"Prepared by {m.get('consultant_name','')}  ·  "
            f"{m.get('consultant_email','')}  ·  {m.get('consultant_certs','')}")
        self.drawRightString(W_PAGE - 14*mm, 4*mm, f"Page {n} of {total}")


def sev_badge(sev, width=58):
    fg, bg, border = SEV_COLORS.get(sev, (GRAY, GRAY_LIGHT, GRAY))
    style = ParagraphStyle("b", fontName="Helvetica-Bold", fontSize=7,
                           textColor=fg, alignment=TA_CENTER)
    return Table([[Paragraph(sev, style)]], colWidths=[width],
        style=TableStyle([
            ("BACKGROUND",   (0,0),(-1,-1), bg),
            ("BOX",          (0,0),(-1,-1), 0.5, border),
            ("TOPPADDING",   (0,0),(-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1), 3),
        ]))

def status_cell(status):
    if status == "PASS":
        return Paragraph("✓ PASS", STYLES["pass"])
    elif status == "FAIL":
        return Paragraph("✗ FAIL", STYLES["fail"])
    else:
        return Paragraph("— ERR",  STYLES["na"])


def generate_pdf(output_path, consultant, client, creds,
                 bucket_names, all_results, findings, counts, total_findings, score, rating):

    scan_date = date.today().strftime("%B %d, %Y")
    scan_time = datetime.now().strftime("%H:%M UTC")

    meta = {
        "client_name":      client["name"],
        "consultant_name":  consultant["name"],
        "consultant_email": consultant["email"],
        "consultant_certs": consultant["certs"],
    }

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=28*mm, bottomMargin=18*mm,
        title="S3 Exposure Scan Report",
        author=consultant["name"],
    )

    story = []

    # ── COVER ─────────────────────────────────────────────────────────────────
    score_color = (RED if score < 50 else ORANGE if score < 70 else GREEN).hexval()
    cover = Table([[
        Table([
            [Paragraph("☁️ S3 EXPOSURE", STYLES["cover_title"])],
            [Paragraph("SCAN REPORT",    STYLES["cover_title"])],
            [Spacer(1, 8)],
            [Paragraph(f"Client: {client['name']}",          STYLES["cover_sub"])],
            [Paragraph(f"Industry: {client['industry']}",    STYLES["cover_meta"])],
            [Paragraph(f"AWS Account: {creds['account_id']}",STYLES["cover_meta"])],
            [Paragraph(f"Scan Date: {scan_date} {scan_time}",STYLES["cover_meta"])],
            [Paragraph(f"Buckets Scanned: {len(bucket_names)}",STYLES["cover_meta"])],
            [Spacer(1, 10)],
            [HRFlowable(width="100%", thickness=1, color=colors.HexColor("#30363D"))],
            [Spacer(1, 10)],
            [Paragraph(
                f'<font color="{score_color}" size="18"><b>{score}/100</b></font>  '
                f'<font color="#8B949E" size="10">— {rating}</font>',
                ParagraphStyle("sc", fontName="Helvetica-Bold", fontSize=18,
                               textColor=WHITE, leading=24))],
            [Paragraph(f"Total Findings: {total_findings}  |  "
                       f"Critical: {counts['CRITICAL']}  High: {counts['HIGH']}  "
                       f"Medium: {counts['MEDIUM']}  Low: {counts['LOW']}",
                       STYLES["cover_meta"])],
            [Spacer(1, 20)],
            [HRFlowable(width="100%", thickness=1, color=colors.HexColor("#30363D"))],
            [Spacer(1, 10)],
            [Paragraph(f"Consultant: {consultant['name']}",  STYLES["cover_sub"])],
            [Paragraph(consultant["title"],                  STYLES["cover_meta"])],
            [Paragraph(consultant["email"],                  STYLES["cover_meta"])],
            [Paragraph(consultant["certs"],                  STYLES["cover_meta"])],
            [Spacer(1, 20)],
            [Paragraph("⚠  CONFIDENTIAL — For authorized recipients only", STYLES["cover_warn"])],
        ], colWidths=[CONTENT_W],
           style=TableStyle([
               ("BACKGROUND",    (0,0),(-1,-1), DARK),
               ("LEFTPADDING",   (0,0),(-1,-1), 20),
               ("RIGHTPADDING",  (0,0),(-1,-1), 20),
               ("TOPPADDING",    (0,0),(-1,-1), 4),
               ("BOTTOMPADDING", (0,0),(-1,-1), 4),
           ]))
    ]], colWidths=[CONTENT_W],
       style=TableStyle([
           ("BACKGROUND",    (0,0),(-1,-1), DARK),
           ("TOPPADDING",    (0,0),(-1,-1), 45),
           ("BOTTOMPADDING", (0,0),(-1,-1), 45),
           ("LEFTPADDING",   (0,0),(-1,-1), 0),
           ("RIGHTPADDING",  (0,0),(-1,-1), 0),
       ]))
    story += [cover, PageBreak()]

    # ── TABLE OF CONTENTS ─────────────────────────────────────────────────────
    story.append(Paragraph("Table of Contents", STYLES["section"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=10))
    for item in ["1.  Executive Summary",
                 "2.  Buckets Scanned — Overview",
                 "3.  Security Check Results — Bucket Matrix",
                 "4.  Detailed Findings",
                 "5.  Remediation Roadmap",
                 "6.  Appendix — Check Definitions"]:
        story.append(Paragraph(item, STYLES["toc"]))
    story.append(PageBreak())

    # ── 1. EXECUTIVE SUMMARY ──────────────────────────────────────────────────
    story.append(Paragraph("1. Executive Summary", STYLES["section"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=10))

    # Narrative
    affected = len(set(f["bucket"] for f in findings))
    story.append(Paragraph(
        f"This S3 Exposure Scan was conducted on the {client['name']} AWS environment "
        f"on {scan_date}. The scan assessed {len(bucket_names)} S3 bucket(s) across "
        f"10 security checks covering public access, encryption, logging, resilience, "
        f"access control, and data governance. "
        f"{affected} of {len(bucket_names)} bucket(s) have at least one failing check. "
        f"A total of {total_findings} finding(s) were identified: "
        f"{counts['CRITICAL']} Critical, {counts['HIGH']} High, "
        f"{counts['MEDIUM']} Medium, and {counts['LOW']} Low severity. "
        f"The overall S3 security posture score is {score}/100 — rated {rating}.",
        STYLES["body"]
    ))
    story.append(Spacer(1, 12))

    # Score box
    score_color_obj = RED if score < 50 else ORANGE if score < 70 else GREEN
    LABEL_W = 68*mm
    RIGHT_W = CONTENT_W - LABEL_W

    left_panel = Table([
        [Paragraph(f'<font size="40" color="{score_color_obj.hexval()}"><b>{score}</b></font>',
                   ParagraphStyle("sc", alignment=TA_CENTER, leading=46, fontName="Helvetica-Bold"))],
        [Paragraph('<font size="9" color="#6E7681">out of 100</font>',
                   ParagraphStyle("sc2", alignment=TA_CENTER, leading=12))],
        [Spacer(1, 4)],
        [Paragraph('<font size="8" color="#6E7681"><b>S3 SECURITY SCORE</b></font>',
                   ParagraphStyle("sc3", alignment=TA_CENTER, fontName="Helvetica-Bold", leading=11))],
        [Paragraph(f'<font size="9" color="{score_color_obj.hexval()}"><b>{rating}</b></font>',
                   ParagraphStyle("sc4", alignment=TA_CENTER, fontName="Helvetica-Bold", leading=13))],
    ], colWidths=[LABEL_W],
       style=TableStyle([
           ("BACKGROUND",    (0,0),(-1,-1), GRAY_LIGHT),
           ("ALIGN",         (0,0),(-1,-1), "CENTER"),
           ("TOPPADDING",    (0,0),(-1,-1), 3),
           ("BOTTOMPADDING", (0,0),(-1,-1), 3),
           ("TOPPADDING",    (0,0),(0,0),   18),
           ("BOTTOMPADDING", (0,4),(-1,-1), 18),
       ]))

    IW = RIGHT_W - 32*mm
    breakdown = Table([
        [Paragraph('<b>Critical</b>', ParagraphStyle("s", fontSize=9, fontName="Helvetica-Bold", textColor=RED)),
         Paragraph(f'<b>{counts["CRITICAL"]}</b>', ParagraphStyle("v", fontSize=13, fontName="Helvetica-Bold", textColor=RED, alignment=TA_RIGHT))],
        [Paragraph('<b>High</b>', ParagraphStyle("s", fontSize=9, fontName="Helvetica-Bold", textColor=ORANGE)),
         Paragraph(f'<b>{counts["HIGH"]}</b>', ParagraphStyle("v", fontSize=13, fontName="Helvetica-Bold", textColor=ORANGE, alignment=TA_RIGHT))],
        [Paragraph('<b>Medium</b>', ParagraphStyle("s", fontSize=9, fontName="Helvetica-Bold", textColor=BLUE)),
         Paragraph(f'<b>{counts["MEDIUM"]}</b>', ParagraphStyle("v", fontSize=13, fontName="Helvetica-Bold", textColor=BLUE, alignment=TA_RIGHT))],
        [Paragraph('<b>Low</b>', ParagraphStyle("s", fontSize=9, fontName="Helvetica-Bold", textColor=GREEN)),
         Paragraph(f'<b>{counts["LOW"]}</b>', ParagraphStyle("v", fontSize=13, fontName="Helvetica-Bold", textColor=GREEN, alignment=TA_RIGHT))],
        [Paragraph('<b>Total</b>', ParagraphStyle("s", fontSize=9, fontName="Helvetica-Bold", textColor=DARK)),
         Paragraph(f'<b>{total_findings}</b>', ParagraphStyle("v", fontSize=13, fontName="Helvetica-Bold", textColor=DARK, alignment=TA_RIGHT))],
    ], colWidths=[IW, RIGHT_W - 16*mm - IW],
       style=TableStyle([
           ("LINEBELOW",     (0,0),(-1,-2), 0.5, colors.HexColor("#E6EDF3")),
           ("TOPPADDING",    (0,0),(-1,-1), 5),
           ("BOTTOMPADDING", (0,0),(-1,-1), 5),
       ]))

    right_panel = Table([
        [Paragraph('<b>Finding Breakdown</b>',
                   ParagraphStyle("fb", fontSize=10, fontName="Helvetica-Bold", textColor=DARK, leading=14))],
        [breakdown],
    ], colWidths=[RIGHT_W],
       style=TableStyle([
           ("BACKGROUND",   (0,0),(-1,-1), WHITE),
           ("LEFTPADDING",  (0,0),(-1,-1), 16),
           ("RIGHTPADDING", (0,0),(-1,-1), 16),
           ("TOPPADDING",   (0,0),(-1,-1), 14),
           ("BOTTOMPADDING",(0,0),(-1,-1), 14),
           ("BOX",          (0,0),(-1,-1), 0.5, colors.HexColor("#E6EDF3")),
       ]))

    story.append(Table([[left_panel, right_panel]], colWidths=[LABEL_W, RIGHT_W],
        style=TableStyle([
            ("BOX",          (0,0),(-1,-1), 1, colors.HexColor("#E6EDF3")),
            ("VALIGN",       (0,0),(-1,-1), "MIDDLE"),
            ("LEFTPADDING",  (0,0),(-1,-1), 0),
            ("RIGHTPADDING", (0,0),(-1,-1), 0),
            ("TOPPADDING",   (0,0),(-1,-1), 0),
            ("BOTTOMPADDING",(0,0),(-1,-1), 0),
        ])))
    story.append(PageBreak())

    # ── 2. BUCKETS SCANNED ────────────────────────────────────────────────────
    story.append(Paragraph("2. Buckets Scanned — Overview", STYLES["section"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=10))

    bucket_rows = [[
        Paragraph("<b>#</b>",          ParagraphStyle("h", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
        Paragraph("<b>Bucket Name</b>",ParagraphStyle("h", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE)),
        Paragraph("<b>Findings</b>",   ParagraphStyle("h", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER)),
        Paragraph("<b>Worst Sev</b>",  ParagraphStyle("h", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER)),
        Paragraph("<b>Status</b>",     ParagraphStyle("h", fontSize=9, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER)),
    ]]

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 9}
    for i, bucket in enumerate(bucket_names, 1):
        b_findings = [f for f in findings if f["bucket"] == bucket]
        count      = len(b_findings)
        worst_sev  = min((f["severity"] for f in b_findings), key=lambda s: sev_order[s], default=None)
        ok         = count == 0

        if worst_sev:
            fg, bg, _ = SEV_COLORS[worst_sev]
            sev_cell  = Paragraph(worst_sev,
                ParagraphStyle("ws", fontSize=8, fontName="Helvetica-Bold",
                               textColor=fg, alignment=TA_CENTER))
        else:
            sev_cell = Paragraph("—", ParagraphStyle("ws", fontSize=8, textColor=GRAY, alignment=TA_CENTER))

        bucket_rows.append([
            Paragraph(str(i), ParagraphStyle("n", fontSize=9, alignment=TA_CENTER)),
            Paragraph(bucket, ParagraphStyle("bn", fontSize=8, fontName="Courier", textColor=DARK)),
            Paragraph(str(count) if count else "0",
                ParagraphStyle("c", fontSize=9, fontName="Helvetica-Bold",
                               textColor=RED if count else GREEN, alignment=TA_CENTER)),
            sev_cell,
            Paragraph("✓ CLEAN" if ok else "✗ ISSUES",
                ParagraphStyle("st", fontSize=8, fontName="Helvetica-Bold",
                               textColor=GREEN if ok else RED, alignment=TA_CENTER)),
        ])

    story.append(Table(bucket_rows,
        colWidths=[12*mm, CONTENT_W - 12*mm - 28*mm - 28*mm - 26*mm, 28*mm, 28*mm, 26*mm],
        style=TableStyle([
            ("BACKGROUND",    (0,0),(-1,0),  DARK),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, GRAY_LIGHT]),
            ("TOPPADDING",    (0,0),(-1,-1), 7),
            ("BOTTOMPADDING", (0,0),(-1,-1), 7),
            ("LEFTPADDING",   (0,0),(-1,-1), 8),
            ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#E6EDF3")),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ])))
    story.append(PageBreak())

    # ── 3. BUCKET MATRIX ──────────────────────────────────────────────────────
    story.append(Paragraph("3. Security Check Results — Bucket Matrix", STYLES["section"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=6))
    story.append(Paragraph(
        "Each cell shows whether the bucket passed (✓) or failed (✗) each of the 10 security checks.",
        STYLES["small"]))
    story.append(Spacer(1, 8))

    check_ids   = [c["id"] for c in CHECKS]
    check_abbrs = ["BPA", "ACL", "POL", "ENC", "TLS", "LOG", "VER", "MFA", "XAC", "LCY"]

    # Header
    matrix_rows = [[
        Paragraph("<b>Bucket</b>", ParagraphStyle("h", fontSize=7, fontName="Helvetica-Bold", textColor=WHITE)),
    ] + [
        Paragraph(f"<b>{a}</b>", ParagraphStyle("h", fontSize=6.5, fontName="Helvetica-Bold",
                                                 textColor=WHITE, alignment=TA_CENTER))
        for a in check_abbrs
    ]]

    BUCKET_COL = 65*mm
    CHECK_COL  = (CONTENT_W - BUCKET_COL) / len(check_ids)

    for bucket in bucket_names:
        row = [Paragraph(bucket, ParagraphStyle("bn", fontSize=7, fontName="Courier", textColor=DARK))]
        for cid in check_ids:
            status = all_results[bucket][cid]["status"]
            row.append(status_cell(status))
        matrix_rows.append(row)

    story.append(Table(matrix_rows,
        colWidths=[BUCKET_COL] + [CHECK_COL] * len(check_ids),
        style=TableStyle([
            ("BACKGROUND",    (0,0),(-1,0),  DARK),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, GRAY_LIGHT]),
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ("LEFTPADDING",   (0,0),(-1,-1), 4),
            ("RIGHTPADDING",  (0,0),(-1,-1), 4),
            ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#E6EDF3")),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ])))

    # Legend
    story.append(Spacer(1, 8))
    legend_items = list(zip(check_abbrs, [c["name"] for c in CHECKS]))
    half = len(legend_items) // 2
    leg_rows = [[
        Paragraph(f"<b>{a}</b> — {n}", STYLES["small"]),
        Paragraph(f"<b>{legend_items[i+half][0]}</b> — {legend_items[i+half][1]}", STYLES["small"]),
    ] for i, (a, n) in enumerate(legend_items[:half])]
    story.append(Table(leg_rows, colWidths=[CONTENT_W/2, CONTENT_W/2],
        style=TableStyle([
            ("TOPPADDING",    (0,0),(-1,-1), 3),
            ("BOTTOMPADDING", (0,0),(-1,-1), 3),
            ("LEFTPADDING",   (0,0),(-1,-1), 6),
        ])))
    story.append(PageBreak())

    # ── 4. DETAILED FINDINGS ──────────────────────────────────────────────────
    story.append(Paragraph("4. Detailed Findings", STYLES["section"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=14))

    if not findings:
        story.append(Paragraph("🎉 No findings detected. All buckets passed all 10 security checks.", STYLES["body"]))
    else:
        for f in findings:
            fg, bg, border = SEV_COLORS[f["severity"]]
            header = Table([[
                Paragraph(
                    f'<font color="{fg.hexval()}"><b>[{f["check_id"]}]</b></font>  '
                    f'<b>{f["check_name"]}</b>  '
                    f'<font color="#6E7681" size="8">→  {f["bucket"]}</font>',
                    ParagraphStyle("ft", fontName="Helvetica-Bold", fontSize=10,
                                   textColor=DARK, leading=13)),
                sev_badge(f["severity"]),
            ]], colWidths=[CONTENT_W - 65, 60],
               style=TableStyle([
                   ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
                   ("ALIGN",  (1,0),(-1,-1), "RIGHT"),
               ]))

            body_data = [
                [Paragraph("Bucket",         STYLES["label"]), Paragraph(f["bucket"],      ParagraphStyle("mono", fontName="Courier", fontSize=9, textColor=DARK, leading=12))],
                [Paragraph("Category",       STYLES["label"]), Paragraph(f["category"],    STYLES["body"])],
                [Paragraph("What was found", STYLES["label"]), Paragraph(f["detail"],      STYLES["body"])],
                [Paragraph("Description",    STYLES["label"]), Paragraph(f["description"], STYLES["body"])],
                [Paragraph("Impact",         STYLES["label"]), Paragraph(f["impact"],      STYLES["body"])],
                [Paragraph("Fix",            STYLES["label"]), Paragraph(f["fix"],         STYLES["body"])],
                [Paragraph("Reference",      STYLES["label"]), Paragraph(f["reference"],   STYLES["small"])],
            ]
            body_tbl = Table(body_data, colWidths=[28*mm, CONTENT_W - 34*mm],
                style=TableStyle([
                    ("BACKGROUND",    (0,0),(-1,-1), bg),
                    ("TOPPADDING",    (0,0),(-1,-1), 5),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 5),
                    ("LEFTPADDING",   (0,0),(0,-1),  10),
                    ("LEFTPADDING",   (1,0),(1,-1),  6),
                    ("RIGHTPADDING",  (0,0),(-1,-1), 8),
                    ("LINEBELOW",     (0,0),(-1,-2), 0.5, colors.HexColor("#E6EDF3")),
                    ("VALIGN",        (0,0),(-1,-1), "TOP"),
                ]))

            card = Table([[header], [body_tbl]], colWidths=[CONTENT_W],
                style=TableStyle([
                    ("BOX",          (0,0),(-1,-1), 1,   border),
                    ("BACKGROUND",   (0,0),(-1,0),  GRAY_LIGHT),
                    ("TOPPADDING",   (0,0),(-1,0),  8),
                    ("BOTTOMPADDING",(0,0),(-1,0),  8),
                    ("LEFTPADDING",  (0,0),(-1,0),  10),
                    ("RIGHTPADDING", (0,0),(-1,0),  10),
                    ("TOPPADDING",   (0,1),(-1,-1), 0),
                    ("BOTTOMPADDING",(0,1),(-1,-1), 0),
                    ("LEFTPADDING",  (0,1),(-1,-1), 0),
                    ("RIGHTPADDING", (0,1),(-1,-1), 0),
                ]))
            story.append(KeepTogether([card, Spacer(1, 10)]))

    story.append(PageBreak())

    # ── 5. REMEDIATION ROADMAP ────────────────────────────────────────────────
    story.append(Paragraph("5. Remediation Roadmap", STYLES["section"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=10))

    phases = [
        ("Immediate (0–7 days)",    "CRITICAL"),
        ("Short-term (7–30 days)",  "HIGH"),
        ("Medium-term (30–90 days)","MEDIUM"),
        ("Low priority (90+ days)", "LOW"),
    ]
    for phase_label, sev in phases:
        phase_findings = [f for f in findings if f["severity"] == sev]
        if not phase_findings:
            continue
        fg, bg, border = SEV_COLORS[sev]
        ph_header = Table([[
            Paragraph(f'<b>{phase_label}</b>',
                ParagraphStyle("ph", fontName="Helvetica-Bold", fontSize=10, textColor=fg, leading=13)),
            sev_badge(sev),
        ]], colWidths=[CONTENT_W - 65, 60],
           style=TableStyle([("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(1,0),(-1,-1),"RIGHT")]))

        item_rows = []
        for pf in phase_findings:
            item_rows.append([Paragraph(
                f"→  <b>{pf['check_id']}</b>: {pf['check_name']}  "
                f"<font color='#6E7681' size='8'>({pf['bucket']})</font>",
                STYLES["body"])])

        items_tbl = Table(item_rows, colWidths=[CONTENT_W],
            style=TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), bg),
                ("LEFTPADDING",   (0,0),(-1,-1), 16),
                ("TOPPADDING",    (0,0),(-1,-1), 5),
                ("BOTTOMPADDING", (0,0),(-1,-1), 5),
                ("LINEBELOW",     (0,0),(-1,-2), 0.5, colors.HexColor("#E6EDF3")),
            ]))

        # Header row
        ph_card_header = Table([[ph_header]], colWidths=[CONTENT_W],
            style=TableStyle([
                ("BOX",          (0,0),(-1,-1), 1, border),
                ("BACKGROUND",   (0,0),(-1,-1), GRAY_LIGHT),
                ("TOPPADDING",   (0,0),(-1,-1), 8),
                ("BOTTOMPADDING",(0,0),(-1,-1), 8),
                ("LEFTPADDING",  (0,0),(-1,-1), 10),
                ("RIGHTPADDING", (0,0),(-1,-1), 10),
            ]))
        story.append(ph_card_header)
        # Each finding as its own row — allows natural page breaks
        for item_row in item_rows:
            row_tbl = Table([item_row], colWidths=[CONTENT_W],
                style=TableStyle([
                    ("BACKGROUND",    (0,0),(-1,-1), bg),
                    ("LEFTPADDING",   (0,0),(-1,-1), 16),
                    ("RIGHTPADDING",  (0,0),(-1,-1), 8),
                    ("TOPPADDING",    (0,0),(-1,-1), 5),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 5),
                    ("LINEBELOW",     (0,0),(-1,-1), 0.5, colors.HexColor("#E6EDF3")),
                    ("BOX",           (0,0),(-1,-1), 0.5, border),
                ]))
            story.append(row_tbl)
        story.append(Spacer(1, 10))
    story.append(PageBreak())

    # ── 6. APPENDIX ───────────────────────────────────────────────────────────
    story.append(Paragraph("6. Appendix — Check Definitions", STYLES["section"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=GREEN, spaceAfter=10))

    app_rows = [[
        Paragraph("<b>Check ID</b>",    ParagraphStyle("h", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE)),
        Paragraph("<b>Name</b>",        ParagraphStyle("h", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE)),
        Paragraph("<b>Severity</b>",    ParagraphStyle("h", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE, alignment=TA_CENTER)),
        Paragraph("<b>Category</b>",    ParagraphStyle("h", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE)),
        Paragraph("<b>Reference</b>",   ParagraphStyle("h", fontSize=8, fontName="Helvetica-Bold", textColor=WHITE)),
    ]]
    for c in CHECKS:
        fg, _, _ = SEV_COLORS[c["severity"]]
        app_rows.append([
            Paragraph(c["id"],        STYLES["mono"]),
            Paragraph(c["name"],      ParagraphStyle("n", fontSize=8, fontName="Helvetica-Bold", textColor=DARK, leading=11)),
            Paragraph(c["severity"],  ParagraphStyle("sv", fontSize=8, fontName="Helvetica-Bold", textColor=fg, alignment=TA_CENTER, leading=11)),
            Paragraph(c["category"],  STYLES["small"]),
            Paragraph(c["reference"], ParagraphStyle("ref", fontSize=7, textColor=GRAY, leading=10)),
        ])

    story.append(Table(app_rows,
        colWidths=[18*mm, 52*mm, 22*mm, 26*mm, CONTENT_W - 18*mm - 52*mm - 22*mm - 26*mm],
        style=TableStyle([
            ("BACKGROUND",    (0,0),(-1,0),  DARK),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, GRAY_LIGHT]),
            ("TOPPADDING",    (0,0),(-1,-1), 6),
            ("BOTTOMPADDING", (0,0),(-1,-1), 6),
            ("LEFTPADDING",   (0,0),(-1,-1), 7),
            ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#E6EDF3")),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ])))

    story.append(Spacer(1, 20))
    story.append(Paragraph(
        f"This report was prepared by {consultant['name']} ({consultant['title']}) on {scan_date}. "
        f"All findings reflect the state of the AWS S3 environment at the time of scan. "
        f"Remediation should be verified with a re-scan. "
        f"Contact: {consultant['email']}",
        ParagraphStyle("closing", fontName="Helvetica", fontSize=8.5,
                       textColor=GRAY, leading=13, alignment=TA_CENTER)
    ))

    # ── BUILD ─────────────────────────────────────────────────────────────────
    def make_canvas(*args, **kwargs):
        kwargs["meta"] = meta
        return ScanCanvas(*args, **kwargs)

    doc.build(story, canvasmaker=make_canvas)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        # Step 1 — collect inputs
        consultant, client, creds, output_path = collect_inputs()

        # Step 2 — connect & scan
        sep("CONNECTING TO AWS")
        s3 = connect_aws(creds)
        print(f"  {green('✓')} Connected to AWS ({creds['region']})")

        bucket_names = list_buckets(s3)
        if not bucket_names:
            print(yellow("  ⚠  No S3 buckets found in this account."))
            sys.exit(0)
        print(f"  {green('✓')} Found {len(bucket_names)} bucket(s)\n")

        all_results = scan_all_buckets(s3, bucket_names)

        # Step 3 — process & build PDF
        findings               = build_findings(all_results)
        counts, total, score, rating = calc_score(all_results)

        sep("GENERATING PDF REPORT")
        print(f"  Score:    {score}/100 — {rating}")
        print(f"  Findings: {total}  (Critical:{counts['CRITICAL']} High:{counts['HIGH']} Medium:{counts['MEDIUM']} Low:{counts['LOW']})")
        print(f"  Output:   {output_path}\n")

        generate_pdf(output_path, consultant, client, creds,
                     bucket_names, all_results, findings, counts, total, score, rating)

        print(f"\n{bold('╔══════════════════════════════════════════════════════════╗')}")
        print(f"{bold('║')}  {green('✅ REPORT READY')}: {output_path:<38}{bold('║')}")
        print(f"{bold('╚══════════════════════════════════════════════════════════╝')}\n")

    except KeyboardInterrupt:
        print(f"\n\n  {yellow('⚠  Cancelled. No report generated.')}\n")
