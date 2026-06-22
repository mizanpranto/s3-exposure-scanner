"""
S3 Exposure Scanner — Demo Report Generator
=============================================
Generates a realistic sample PDF report with mock scan results.
Use this to show clients what they will receive before hiring you.

Usage: python generate_demo.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from scan import (
    generate_pdf, build_findings, calc_score,
    CHECK_MAP, CHECKS
)

# ─────────────────────────────────────────────────────────────────────────────
# MOCK DATA — 8 realistic S3 buckets a typical startup would have
# ─────────────────────────────────────────────────────────────────────────────
CONSULTANT = {
    "name":  "Your Name",
    "title": "Cloud Security Consultant",
    "email": "hello@yoursite.com",
    "certs": "AWS SAA Certified | ISO 27001 | NIST | GDPR",
}

CLIENT = {
    "name":     "FinVault Technologies Ltd",
    "industry": "Fintech / SaaS",
    "contact":  "CTO",
}

CREDS = {
    "account_id": "234567890123",
    "region":     "us-east-1",
}

# Bucket names that look realistic for a fintech startup
BUCKETS = [
    "finvault-prod-customer-documents",
    "finvault-prod-database-backups",
    "finvault-prod-app-assets",
    "finvault-staging-uploads",
    "finvault-prod-audit-logs",
    "finvault-dev-test-data",
    "finvault-prod-invoices",
    "finvault-static-website",
]

# ─────────────────────────────────────────────────────────────────────────────
# MOCK SCAN RESULTS — realistic findings for each bucket
# PASS = secure   FAIL = vulnerable   ERROR = permission denied
# ─────────────────────────────────────────────────────────────────────────────
MOCK_RESULTS = {
    "finvault-prod-customer-documents": {
        "S3-001": {"status": "FAIL",  "detail": "BlockPublicAcls=False, IgnorePublicAcls=False, BlockPublicPolicy=False, RestrictPublicBuckets=False"},
        "S3-002": {"status": "FAIL",  "detail": "Public ACL grant found: AllUsers → READ"},
        "S3-003": {"status": "FAIL",  "detail": "Public policy statements: Action: s3:GetObject"},
        "S3-004": {"status": "FAIL",  "detail": "No default encryption configured. Objects stored in plaintext."},
        "S3-005": {"status": "FAIL",  "detail": "No bucket policy — HTTP access is allowed by default."},
        "S3-006": {"status": "FAIL",  "detail": "Server access logging is disabled."},
        "S3-007": {"status": "FAIL",  "detail": "Versioning: Never enabled"},
        "S3-008": {"status": "FAIL",  "detail": "MFA Delete: Disabled"},
        "S3-009": {"status": "PASS",  "detail": "No cross-account principals detected in bucket policy."},
        "S3-010": {"status": "FAIL",  "detail": "No lifecycle policy configured. Objects retained indefinitely."},
    },
    "finvault-prod-database-backups": {
        "S3-001": {"status": "FAIL",  "detail": "BlockPublicAcls=True, IgnorePublicAcls=True, BlockPublicPolicy=False, RestrictPublicBuckets=False"},
        "S3-002": {"status": "PASS",  "detail": "No public ACL grants detected."},
        "S3-003": {"status": "PASS",  "detail": "No unrestricted Principal: * statements found."},
        "S3-004": {"status": "FAIL",  "detail": "No default encryption configured. Objects stored in plaintext."},
        "S3-005": {"status": "FAIL",  "detail": "No HTTPS-enforcement deny rule in bucket policy. HTTP access is allowed."},
        "S3-006": {"status": "FAIL",  "detail": "Server access logging is disabled."},
        "S3-007": {"status": "PASS",  "detail": "Versioning: Enabled"},
        "S3-008": {"status": "FAIL",  "detail": "MFA Delete: Disabled"},
        "S3-009": {"status": "PASS",  "detail": "No cross-account principals detected in bucket policy."},
        "S3-010": {"status": "FAIL",  "detail": "No lifecycle policy configured. Objects retained indefinitely."},
    },
    "finvault-prod-app-assets": {
        "S3-001": {"status": "PASS",  "detail": "All 4 Block Public Access settings enabled."},
        "S3-002": {"status": "PASS",  "detail": "No public ACL grants detected."},
        "S3-003": {"status": "PASS",  "detail": "No unrestricted Principal: * statements found."},
        "S3-004": {"status": "PASS",  "detail": "Encryption: AES256"},
        "S3-005": {"status": "PASS",  "detail": "Bucket policy enforces HTTPS-only (aws:SecureTransport deny rule found)."},
        "S3-006": {"status": "FAIL",  "detail": "Server access logging is disabled."},
        "S3-007": {"status": "PASS",  "detail": "Versioning: Enabled"},
        "S3-008": {"status": "FAIL",  "detail": "MFA Delete: Disabled"},
        "S3-009": {"status": "FAIL",  "detail": "Cross-account access granted to account(s): 987654321098"},
        "S3-010": {"status": "PASS",  "detail": "2 active lifecycle rule(s) configured."},
    },
    "finvault-staging-uploads": {
        "S3-001": {"status": "FAIL",  "detail": "BlockPublicAcls=False, IgnorePublicAcls=False, BlockPublicPolicy=True, RestrictPublicBuckets=True"},
        "S3-002": {"status": "FAIL",  "detail": "Public ACL grant found: AuthenticatedUsers → READ"},
        "S3-003": {"status": "PASS",  "detail": "No unrestricted Principal: * statements found."},
        "S3-004": {"status": "FAIL",  "detail": "No default encryption configured. Objects stored in plaintext."},
        "S3-005": {"status": "FAIL",  "detail": "No HTTPS-enforcement deny rule in bucket policy."},
        "S3-006": {"status": "FAIL",  "detail": "Server access logging is disabled."},
        "S3-007": {"status": "FAIL",  "detail": "Versioning: Never enabled"},
        "S3-008": {"status": "FAIL",  "detail": "MFA Delete: Disabled"},
        "S3-009": {"status": "PASS",  "detail": "No cross-account principals detected in bucket policy."},
        "S3-010": {"status": "FAIL",  "detail": "No lifecycle policy configured. Objects retained indefinitely."},
    },
    "finvault-prod-audit-logs": {
        "S3-001": {"status": "PASS",  "detail": "All 4 Block Public Access settings enabled."},
        "S3-002": {"status": "PASS",  "detail": "No public ACL grants detected."},
        "S3-003": {"status": "PASS",  "detail": "No unrestricted Principal: * statements found."},
        "S3-004": {"status": "PASS",  "detail": "Encryption: aws:kms with KMS key: ...a1b2c3d4e5f6"},
        "S3-005": {"status": "PASS",  "detail": "Bucket policy enforces HTTPS-only (aws:SecureTransport deny rule found)."},
        "S3-006": {"status": "PASS",  "detail": "Logging → s3://finvault-meta-logs/audit-logs/"},
        "S3-007": {"status": "PASS",  "detail": "Versioning: Enabled"},
        "S3-008": {"status": "FAIL",  "detail": "MFA Delete: Disabled"},
        "S3-009": {"status": "PASS",  "detail": "No cross-account principals detected in bucket policy."},
        "S3-010": {"status": "PASS",  "detail": "1 active lifecycle rule(s) configured."},
    },
    "finvault-dev-test-data": {
        "S3-001": {"status": "FAIL",  "detail": "BlockPublicAcls=False, IgnorePublicAcls=False, BlockPublicPolicy=False, RestrictPublicBuckets=False"},
        "S3-002": {"status": "PASS",  "detail": "No public ACL grants detected."},
        "S3-003": {"status": "FAIL",  "detail": "Public policy statements: Action: s3:* (full access)"},
        "S3-004": {"status": "FAIL",  "detail": "No default encryption configured. Objects stored in plaintext."},
        "S3-005": {"status": "FAIL",  "detail": "No bucket policy HTTPS enforcement found."},
        "S3-006": {"status": "FAIL",  "detail": "Server access logging is disabled."},
        "S3-007": {"status": "FAIL",  "detail": "Versioning: Suspended"},
        "S3-008": {"status": "FAIL",  "detail": "MFA Delete: Disabled"},
        "S3-009": {"status": "PASS",  "detail": "No cross-account principals detected in bucket policy."},
        "S3-010": {"status": "FAIL",  "detail": "No lifecycle policy configured. Objects retained indefinitely."},
    },
    "finvault-prod-invoices": {
        "S3-001": {"status": "FAIL",  "detail": "BlockPublicAcls=True, IgnorePublicAcls=True, BlockPublicPolicy=False, RestrictPublicBuckets=False"},
        "S3-002": {"status": "PASS",  "detail": "No public ACL grants detected."},
        "S3-003": {"status": "PASS",  "detail": "No unrestricted Principal: * statements found."},
        "S3-004": {"status": "FAIL",  "detail": "No default encryption configured. Objects stored in plaintext."},
        "S3-005": {"status": "FAIL",  "detail": "No HTTPS-enforcement deny rule in bucket policy."},
        "S3-006": {"status": "FAIL",  "detail": "Server access logging is disabled."},
        "S3-007": {"status": "FAIL",  "detail": "Versioning: Never enabled"},
        "S3-008": {"status": "FAIL",  "detail": "MFA Delete: Disabled"},
        "S3-009": {"status": "FAIL",  "detail": "Cross-account access granted to account(s): 111222333444"},
        "S3-010": {"status": "FAIL",  "detail": "No lifecycle policy configured. Objects retained indefinitely."},
    },
    "finvault-static-website": {
        "S3-001": {"status": "FAIL",  "detail": "BlockPublicAcls=False, IgnorePublicAcls=False, BlockPublicPolicy=False, RestrictPublicBuckets=False"},
        "S3-002": {"status": "FAIL",  "detail": "Public ACL grant found: AllUsers → READ"},
        "S3-003": {"status": "FAIL",  "detail": "Public policy statements: Action: s3:GetObject"},
        "S3-004": {"status": "PASS",  "detail": "Encryption: AES256"},
        "S3-005": {"status": "FAIL",  "detail": "No HTTPS-enforcement deny rule in bucket policy."},
        "S3-006": {"status": "FAIL",  "detail": "Server access logging is disabled."},
        "S3-007": {"status": "FAIL",  "detail": "Versioning: Never enabled"},
        "S3-008": {"status": "FAIL",  "detail": "MFA Delete: Disabled"},
        "S3-009": {"status": "PASS",  "detail": "No cross-account principals detected in bucket policy."},
        "S3-010": {"status": "FAIL",  "detail": "No lifecycle policy configured. Objects retained indefinitely."},
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# GENERATE
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║   S3 EXPOSURE SCANNER — DEMO REPORT GENERATOR          ║")
    print("╚══════════════════════════════════════════════════════════╝\n")

    findings             = build_findings(MOCK_RESULTS)
    counts, total, score, rating = calc_score(MOCK_RESULTS)

    print(f"  Client:   {CLIENT['name']}")
    print(f"  Buckets:  {len(BUCKETS)}")
    print(f"  Findings: {total}  "
          f"(Critical:{counts['CRITICAL']} High:{counts['HIGH']} "
          f"Medium:{counts['MEDIUM']} Low:{counts['LOW']})")
    print(f"  Score:    {score}/100 — {rating}")
    print(f"\n  ⏳ Generating PDF...\n")

    output = "s3_scan_finvault_DEMO.pdf"
    generate_pdf(
        output, CONSULTANT, CLIENT, CREDS,
        BUCKETS, MOCK_RESULTS, findings,
        counts, total, score, rating
    )

    print(f"  ✅ Done: {output}")
    print(f"\n  Upload this to GitHub as a sample output.")
    print(f"  Send it to prospects to show what they'll receive.\n")
