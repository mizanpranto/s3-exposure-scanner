# 🔍 S3 Exposure Scanner

> **Scans every S3 bucket in an AWS account across 10 security checks.**  
> Built for cloud security consultants. Outputs a client-ready PDF report in minutes.  
> No code editing required — interactive terminal wizard guides you through setup.

---

## 📋 What It Does

Run one command. Enter credentials interactively. Receive a professional PDF report.

The scanner checks every S3 bucket across **10 security controls** covering public access, encryption, logging, resilience, and compliance — then generates a branded PDF report ready to deliver to your client.

---

## 🔒 10 Security Checks

| ID | Check | Severity | Compliance |
|----|-------|----------|------------|
| S3-001 | Block Public Access Disabled | 🔴 CRITICAL | CIS 2.1.5, PCI-DSS 1.3 |
| S3-002 | Bucket Publicly Accessible via ACL | 🔴 CRITICAL | CIS 2.1.5, GDPR Art.32 |
| S3-003 | Bucket Publicly Accessible via Policy | 🔴 CRITICAL | CIS 2.1.5 |
| S3-004 | No Default Encryption | 🟠 HIGH | CIS 2.1.1, PCI-DSS 3.4, SOC 2 CC6.1 |
| S3-005 | HTTP Access Allowed (No HTTPS Enforcement) | 🟠 HIGH | CIS 2.1.2, PCI-DSS 4.1 |
| S3-006 | Server Access Logging Disabled | 🟠 HIGH | CIS 2.1.3, ISO 27001 A.12.4 |
| S3-007 | Versioning Disabled | 🟠 HIGH | NIST SP 800-53 CP-9 |
| S3-008 | MFA Delete Disabled | 🟠 HIGH | PCI-DSS 8.3 |
| S3-009 | Cross-Account Access in Bucket Policy | 🔵 MEDIUM | ISO 27001 A.15 |
| S3-010 | No Lifecycle Policy Configured | 🔵 MEDIUM | GDPR Art.5(1)(e) |

---

## 📄 Report Sections

The generated PDF contains:

1. **Cover page** — client name, AWS account ID, scan date, security score, consultant credentials
2. **Executive summary** — narrative + score box with Critical/High/Medium/Low breakdown
3. **Buckets overview table** — every bucket with finding count and worst severity
4. **Security matrix** — pass/fail grid for all buckets × all 10 checks at a glance
5. **Detailed findings** — one card per failed check with bucket name, what was found, impact, and fix
6. **Remediation roadmap** — prioritised fix plan grouped by severity (Immediate → Low priority)
7. **Appendix** — all 10 check definitions with compliance references

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install boto3 reportlab

# 2. Run the scanner
python scan.py

# 3. Follow the interactive wizard — done!
```

---

## 🖥️ What the Wizard Looks Like

```
╔══════════════════════════════════════════════════════════╗
║        S3 EXPOSURE SCANNER                              ║
║        Cloud Security Consultant Tool                   ║
╚══════════════════════════════════════════════════════════╝

──────────────────────────────────────────────────────────
  STEP 1 of 3 — YOUR CONSULTANT DETAILS
──────────────────────────────────────────────────────────
  Your full name [Your Name]: Mizanur Rahman Pranto
  Your title: Cloud Security Consultant
  Your email: mprantox41@gmail.com
  Your certifications: 

──────────────────────────────────────────────────────────
  STEP 2 of 3 — CLIENT DETAILS
──────────────────────────────────────────────────────────
  Client company name: FinVault Technologies Ltd
  Client industry: Fintech / SaaS
  Client contact name: CTO

──────────────────────────────────────────────────────────
  STEP 3 of 3 — AWS CREDENTIALS
──────────────────────────────────────────────────────────
  (Read-only credentials — scanner never writes to your AWS account)

  AWS Access Key ID: ****************
  AWS Secret Access Key: ****************
  AWS Session Token (optional): (press Enter to skip)
  Default region [us-east-1]: ap-southeast-1
  AWS Account ID: 234567890123
  Output PDF filename [s3_scan_finvault_20260703.pdf]:

──────────────────────────────────────────────────────────
  CONNECTING TO AWS
──────────────────────────────────────────────────────────
  ✓ Connected to AWS (ap-southeast-1)
  ✓ Found 8 bucket(s)

──────────────────────────────────────────────────────────
  SCANNING BUCKETS
──────────────────────────────────────────────────────────
  [ 8/ 8]  finvault-static-website
  ✓ Scanned 8 bucket(s) across 10 checks.

──────────────────────────────────────────────────────────
  GENERATING PDF REPORT
──────────────────────────────────────────────────────────
  Score:    0/100 — CRITICAL RISK
  Findings: 51  (Critical:12 High:31 Medium:8 Low:0)
  Output:   s3_scan_finvault_20260703.pdf

╔══════════════════════════════════════════════════════════╗
║  ✅ REPORT READY: s3_scan_finvault_20260703.pdf         ║
╚══════════════════════════════════════════════════════════╝
```

---

## 🔑 Required AWS IAM Permissions

The scanner is **read-only** — it never modifies your AWS environment.

Create a read-only IAM policy with these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:GetBucketVersioning",
        "s3:GetBucketLifecycleConfiguration",
        "s3:GetBucketPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 📊 Security Score Calculation

| Severity | Deduction per finding |
|----------|-----------------------|
| 🔴 CRITICAL | −20 points |
| 🟠 HIGH | −10 points |
| 🔵 MEDIUM | −5 points |
| 🟢 LOW | −2 points |

| Score | Rating |
|-------|--------|
| 80–100 | ✅ GOOD |
| 60–79 | 🟡 FAIR |
| 40–59 | 🟠 NEEDS IMPROVEMENT |
| 0–39 | 🔴 CRITICAL RISK |

---

## 📁 Project Structure

```
s3-exposure-scanner/
├── scan.py               # Main scanner + PDF generator (run this)
├── generate_demo.py      # Demo report with mock data (no AWS needed)
├── s3_scan_finvault_DEMO.pdf   # Sample output
└── README.md             # This file
```

---

## 🧪 Try It Without AWS Credentials

Want to see the report before connecting a real account?

```bash
python generate_demo.py
# Generates: s3_scan_finvault_DEMO.pdf
```

This generates a realistic report using mock data for a fictional fintech company — 8 buckets, 51 findings, same format as a real scan.



## 👤 About

Built by **Mizanur Rahman Pranto** — Cyber Security Consultant  
Specialising in AWS security assessments for startups and SMEs globally.


- 💼 [LinkedIn](https://www.linkedin.com/in/mrpranto1997/)
- 📧 mprantox41@gmail.com


**Available for AWS Security Assessments** — [Book a free 30-min call](mailto:mprantox41@gmail.com)

---

## ⚠️ Disclaimer

For use by qualified security consultants. The scanner requires valid AWS credentials with appropriate read-only permissions. It does not modify any AWS resources. Sample outputs use fictional data for demonstration only.
