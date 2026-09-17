# AWS Cloud Security: IAM Least Privilege Architecture & MFA Enforcement (Unit 2)

> **Course**: Cloud Security & Architecture (PBL)  
> **Student**: Saif Pathan  
> **Repository**: [https://github.com/saifpathan9969/CSA-UNIT-2-](https://github.com/saifpathan9969/CSA-UNIT-2-)  
> **Related**: [Unit 1 Repository (3-Tier Web App & Honeypot Analysis)](https://github.com/saifpathan9969/CSA)

---

## 📋 Executive Overview

This repository contains the complete deliverables for **Unit 2: IAM & Least Privilege Enforcement** of the Cloud Security Problem-Based Learning (PBL) curriculum. 

The project delivers a production-grade AWS Identity and Access Management (IAM) security model implemented via **Terraform Infrastructure as Code (IaC)**, strictly adhering to the **Principle of Least Privilege (PoLP)**, **Zero Trust principles**, and the **CIS AWS Foundations Benchmark**.

### Key Architecture Highlights
1. **Three Role-Based IAM User Groups**: `Admins`, `Developers`, and `Auditors` with fine-grained Customer Managed Policies.
2. **Mandatory MFA Enforcement**: Strict multi-factor authentication enforcement (`aws:MultiFactorAuthPresent: true`) denying all AWS API calls for unauthenticated sessions.
3. **Credential-Free EC2-to-S3 Role Delegation**: Complete elimination of long-lived access keys using an IAM Role, Instance Profile, and automated STS token rotation via IMDSv2.
4. **Hardened S3 Storage**: Encrypted at rest (AES-256 KMS), versioned, private, and enforcing HTTPS/TLS 1.2+ transport security.

---

## 📸 Architecture & Implementation Screenshots

### 1. AWS IAM Console – User Groups & MFA Enforcement
Real AWS Management Console view displaying the three distinct user groups (`Admins`, `Developers`, `Auditors`) with attached least privilege policies and active MFA requirement badges:

![AWS IAM Management Console](assets/iam_console_user_groups.png)

---

### 2. AWS CLI Terminal – Least Privilege Verification & Access Control
Authentic terminal session verifying role assumption from EC2 (`aws sts get-caller-identity`), successful S3 bucket access, and explicit/implicit `AccessDenied` enforcement on unauthorized operations:

![AWS CLI Terminal Verification](assets/iam_cli_verification_screenshot.png)

---

### 3. IAM Least Privilege Security Model Diagram
Technical design detailing role delegation, STS temporary credentials, and group policy boundaries:

![IAM Architecture Diagram](assets/iam_architecture_diagram.png)

---

## 🗂️ Repository Structure

```
CSA-UNIT-2-/
├── README.md                                          # This documentation
├── terraform/                                         # Terraform Infrastructure as Code
│   ├── main.tf                                        # AWS Provider, versions & account data
│   ├── groups.tf                                      # IAM Groups (Admins, Devs, Auditors) & MFA policy
│   ├── ec2_s3_role.tf                                 # EC2-to-S3 IAM Role + Instance Profile
│   ├── s3.tf                                          # Hardened S3 bucket with TLS-only policy
│   ├── variables.tf                                   # Project variables & environment config
│   └── outputs.tf                                     # Role ARNs, Group ARNs, Bucket names
├── docs/
│   └── UNIT2_IAM_LEAST_PRIVILEGE.md                   # Comprehensive security analysis report
└── assets/
    ├── iam_console_user_groups.png                    # Real AWS console screenshot
    ├── iam_cli_verification_screenshot.png            # Real AWS CLI test terminal screenshot
    └── iam_architecture_diagram.png                  # Technical architecture diagram
```

---

## 👥 IAM User Groups & Permission Matrix

| Group | Intended Persona | Assigned Policies | MFA Condition | Access Level |
|---|---|---|---|---|
| **Admins** | Cloud Architects & SysAdmins | `AdministratorAccess`, `EnforceMFAPolicy` | **Mandatory** (`Bool: {aws:MultiFactorAuthPresent: true}`) | Full administration (blocked without active MFA) |
| **Developers** | Application Engineers | `DeveloperLeastPrivilegePolicy`, `EnforceMFAPolicy` | **Mandatory** | Read/Write to project S3 bucket; EC2 lifecycle operations; CloudWatch Logs. **Zero** IAM or Billing permissions. |
| **Auditors** | Compliance & Security Auditors | `SecurityAudit`, `AuditorCompliancePolicy`, `EnforceMFAPolicy` | **Mandatory** | **Read-Only** inspection across AWS Config, CloudTrail, GuardDuty, and IAM. Cannot create or modify resources. |

---

## 🔑 Credential-Free EC2-to-S3 Role Architecture

### Why IAM Roles Supersede Access Keys
Hardcoding `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in application code, configuration files, or environment variables is one of the leading causes of cloud breaches. 

In this architecture:
- **Trust Relationship**: The IAM Role explicitly trusts the `ec2.amazonaws.com` service principal.
- **Automated Rotation**: The AWS EC2 Instance Metadata Service (IMDSv2) automatically issues short-lived (1 to 6 hour) STS credentials.
- **Zero Key Leakage**: No credentials are ever stored on disk or in source control.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "ec2.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

---

## 🚀 Deployment Guide

### Prerequisites
- [Terraform >= 1.3.0](https://www.terraform.io/downloads.html)
- AWS CLI v2 configured with administrator privileges

### Commands
```bash
# Clone the repository
git clone https://github.com/saifpathan9969/CSA-UNIT-2-.git
cd CSA-UNIT-2-/terraform

# Initialize Terraform AWS provider
terraform init

# Review execution plan
terraform plan -out=tfplan

# Apply infrastructure
terraform apply tfplan
```

### Verification
```bash
# 1. Verify IAM Groups
aws iam list-groups --output table

# 2. Check attached group policies
aws iam list-attached-group-policies --group-name Admins
aws iam list-attached-group-policies --group-name Developers
aws iam list-attached-group-policies --group-name Auditors

# 3. Test EC2 Instance Profile from within an EC2 instance
aws sts get-caller-identity
aws s3 ls s3://csa-secure-audit-bucket-prod/
```

---

## 🛡️ Security Compliance
- **CIS AWS Foundations Benchmark v1.4.0**: Meets Controls 1.5 (Ensure IAM password policy), 1.10 (Ensure multi-factor authentication is enabled for all IAM users), and 2.1 (Ensure S3 bucket access is restricted).
- **Least Privilege**: All policies avoid wildcard actions (`*`) on critical resources.
- **Data Protection**: TLS 1.2+ mandatory transport security; server-side encryption via AWS KMS.

---

## 📝 License
Academic project for Cloud Security & Architecture PBL curriculum.
