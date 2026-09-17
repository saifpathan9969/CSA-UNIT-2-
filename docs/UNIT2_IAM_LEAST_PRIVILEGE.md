# Unit 2 – IAM Least Privilege Architecture

## 📋 Overview

This document details the **IAM Least Privilege Architecture** implemented for the Cloud Security PBL Unit 2. The implementation creates three IAM groups (Admins, Developers, Auditors) with role-appropriate permissions, mandatory MFA enforcement across all groups, and a credential-less EC2-to-S3 IAM Role that eliminates the need for hardcoded AWS access keys.

---

## 🏗️ Architecture Design

### IAM Group Structure

```
AWS Account
├── IAM Groups (/csa/)
│   ├── csa-iam-admins
│   │   ├── Policy: AdministratorAccess (AWS Managed)
│   │   └── Policy: csa-iam-enforce-mfa (Custom)
│   │
│   ├── csa-iam-developers
│   │   ├── Policy: csa-iam-developer-access (Custom – Least Privilege)
│   │   └── Policy: csa-iam-enforce-mfa (Custom)
│   │
│   └── csa-iam-auditors
│       ├── Policy: SecurityAudit (AWS Managed)
│       ├── Policy: csa-iam-auditor-readonly (Custom)
│       └── Policy: csa-iam-enforce-mfa (Custom)
│
├── IAM Role (/csa/)
│   └── csa-iam-ec2-s3-role
│       ├── Trust: ec2.amazonaws.com
│       ├── Policy: csa-iam-ec2-s3-access (Custom)
│       └── Instance Profile: csa-iam-ec2-s3-instance-profile
│
└── S3 Bucket
    └── csa-pbl-app-data-bucket
        ├── Encryption: AES-256 (SSE-S3)
        ├── Versioning: Enabled
        ├── Public Access: Blocked
        └── Bucket Policy: SSL/TLS Only
```

---

## 🔐 MFA Enforcement Policy — Deep Dive

### Policy Logic

The MFA enforcement policy is the **most critical** component of this architecture. It ensures that **no AWS API call can succeed** unless the user has authenticated with a Multi-Factor Authentication (MFA) device in their current session.

### How It Works

```
User attempts AWS API call
        │
        ▼
┌─────────────────────────────┐
│  Is the action MFA-related? │
│  (CreateVirtualMFADevice,   │
│   EnableMFADevice, etc.)    │
└──────┬──────────┬───────────┘
       │ YES      │ NO
       ▼          ▼
   ┌────────┐  ┌──────────────────────┐
   │ ALLOW  │  │ Is MFA authenticated │
   │        │  │ in this session?     │
   └────────┘  └───┬──────────┬───────┘
                   │ YES      │ NO
                   ▼          ▼
              ┌────────┐  ┌────────┐
              │ ALLOW  │  │  DENY  │
              │ (check │  │  (all  │
              │ other  │  │ actions│
              │ policies│  │ blocked│
              └────────┘  └────────┘
```

### Policy JSON Breakdown

The policy contains 4 statements:

#### Statement 1: `AllowViewAccountInfo`
```json
{
  "Effect": "Allow",
  "Action": [
    "iam:GetAccountPasswordPolicy",
    "iam:ListVirtualMFADevices"
  ]
}
```
**Purpose**: Allows users to view password policy and existing MFA devices, even before MFA is set up. This is necessary for the initial MFA registration flow.

#### Statement 2: `AllowManageOwnMFA`
```json
{
  "Effect": "Allow",
  "Action": [
    "iam:CreateVirtualMFADevice",
    "iam:EnableMFADevice",
    "iam:ListMFADevices",
    "iam:ResyncMFADevice",
    "iam:DeactivateMFADevice"
  ],
  "Resource": [
    "arn:aws:iam::ACCOUNT:mfa/${aws:username}",
    "arn:aws:iam::ACCOUNT:user/${aws:username}"
  ]
}
```
**Purpose**: Users can manage **their own** MFA devices (register, enable, resync, deactivate) but cannot manage MFA for other users. The `${aws:username}` policy variable ensures the resource is scoped to the requesting user.

#### Statement 3: `AllowManageOwnPasswords`
```json
{
  "Effect": "Allow",
  "Action": ["iam:ChangePassword", "iam:GetUser"],
  "Resource": "arn:aws:iam::ACCOUNT:user/${aws:username}"
}
```
**Purpose**: Users can change their own password and view their own user info.

#### Statement 4: `DenyAllExceptMFASetupWithoutMFA` (The Core)
```json
{
  "Effect": "Deny",
  "NotAction": [
    "iam:CreateVirtualMFADevice",
    "iam:EnableMFADevice",
    "iam:GetUser",
    "iam:ChangePassword",
    "iam:GetAccountPasswordPolicy",
    "iam:ListMFADevices",
    "iam:ListVirtualMFADevices",
    "iam:ResyncMFADevice",
    "sts:GetSessionToken"
  ],
  "Condition": {
    "BoolIfExists": {
      "aws:MultiFactorAuthPresent": "false"
    }
  }
}
```
**Purpose**: This is the enforcement mechanism. It uses `NotAction` + `Deny` to block **everything except** MFA-related actions when MFA is not present in the session. The `BoolIfExists` condition handles both:
- Sessions where MFA has not been used (`"false"`)
- Long-term credentials where the MFA context key doesn't exist

---

## 👥 Group Permission Details

### Admins Group

| Aspect | Details |
|--------|---------|
| **AWS Managed Policy** | `AdministratorAccess` – Full AWS access |
| **Custom Policy** | MFA Enforcement |
| **Effective Access** | Full AWS access, **but only after MFA authentication** |
| **Use Case** | Cloud infrastructure administrators, security engineers |

### Developers Group

| Aspect | Details |
|--------|---------|
| **Custom Policy** | `csa-iam-developer-access` |
| **Allowed Services** | EC2, S3 (specific bucket), CloudWatch, CloudWatch Logs |
| **Region Restriction** | EC2 actions restricted to `us-east-1` only |
| **S3 Restriction** | Only `csa-pbl-app-data-bucket` (not all S3 buckets) |
| **Explicit Denies** | IAM user/group/role management, Billing, Organizations, Account settings |
| **Custom Policy** | MFA Enforcement |
| **Use Case** | Application developers, DevOps engineers (non-admin) |

### Auditors Group

| Aspect | Details |
|--------|---------|
| **AWS Managed Policy** | `SecurityAudit` – Broad read-only security access |
| **Custom Policy** | `csa-iam-auditor-readonly` – Additional read: CloudTrail, Config, GuardDuty, Shield/WAF |
| **Explicit Denies** | All write operations (EC2 launch/terminate, S3 put/delete, IAM create/modify) |
| **Custom Policy** | MFA Enforcement |
| **Use Case** | Security auditors, compliance officers, external audit teams |

---

## 🔄 EC2-to-S3 IAM Role (Credential-less Access)

### Why IAM Roles Instead of Access Keys?

| Hardcoded Access Keys ❌ | IAM Roles ✅ |
|---|---|
| Static credentials stored on instance | Temporary credentials auto-rotated every 6 hours |
| Risk of credential leakage in code/logs | No credentials to leak |
| Manual rotation required | Automatic rotation via STS |
| Compromised key = persistent access | Compromised token expires in hours |
| Difficult to audit who used the key | CloudTrail logs show role assumption with instance ID |

### Architecture

```
┌──────────────────────┐       ┌───────────────────────┐
│    EC2 Instance       │       │    S3 Bucket           │
│                       │       │    (csa-pbl-app-data)  │
│  ┌─────────────────┐ │       │                        │
│  │ Instance Profile │ │       │  ┌──────────────────┐ │
│  │ (auto-attached)  │──────►──│  │ Bucket Policy:   │ │
│  └────────┬────────┘ │ STS   │  │ - SSL/TLS Only   │ │
│           │          │ Temp   │  │ - Block Public   │ │
│  ┌────────▼────────┐ │ Creds  │  └──────────────────┘ │
│  │ IMDSv2          │ │       │                        │
│  │ (Token-based)   │ │       │  Encryption: AES-256   │
│  └─────────────────┘ │       │  Versioning: ON        │
└──────────────────────┘       └───────────────────────┘
```

### How EC2 Gets Temporary Credentials

1. EC2 instance is launched with the **Instance Profile** attached
2. Application on EC2 calls the **Instance Metadata Service (IMDSv2)**:
   ```bash
   # Step 1: Get IMDSv2 token
   TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
     -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
   
   # Step 2: Get temporary credentials
   curl -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/csa-iam-ec2-s3-role
   ```
3. IMDS returns **temporary credentials** (Access Key, Secret Key, Session Token)
4. Credentials are **automatically rotated** before expiry
5. AWS SDKs (boto3, AWS CLI) handle this transparently

### Verification: Testing EC2-to-S3 Access

```bash
# SSH into the EC2 instance (which has the Instance Profile attached)

# Test 1: List the bucket (should succeed)
aws s3 ls s3://csa-pbl-app-data-bucket/

# Test 2: Upload a file (should succeed)
echo "Hello from EC2!" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://csa-pbl-app-data-bucket/test.txt

# Test 3: Download a file (should succeed)
aws s3 cp s3://csa-pbl-app-data-bucket/test.txt /tmp/downloaded.txt

# Test 4: Access a DIFFERENT bucket (should FAIL – least privilege)
aws s3 ls s3://some-other-bucket/
# Error: Access Denied

# Test 5: Verify NO hardcoded credentials exist
env | grep AWS_ACCESS
# (should return empty – no hardcoded keys)

# Test 6: Verify credentials come from Instance Profile
aws sts get-caller-identity
# Returns: Role ARN = arn:aws:sts::ACCOUNT:assumed-role/csa-iam-ec2-s3-role/i-xxxxx
```

---

## 🪣 S3 Bucket Security Controls

| Control | Implementation |
|---------|---------------|
| **Public Access** | All 4 public access block settings enabled |
| **Encryption** | Server-side encryption (AES-256 / SSE-S3) with Bucket Key |
| **Versioning** | Enabled – protects against accidental deletion |
| **Transport Security** | Bucket policy denies any request where `aws:SecureTransport = false` |
| **Access Control** | Only the EC2 IAM Role can read/write objects |

---

## 📁 Terraform Files

| File | Purpose |
|------|---------|
| `main.tf` | Provider configuration, data sources (account ID, region) |
| `groups.tf` | IAM groups (Admins, Developers, Auditors), MFA enforcement policy, group-specific policies |
| `ec2_s3_role.tf` | EC2-to-S3 IAM Role, trust policy, S3 access policy, instance profile |
| `s3.tf` | S3 bucket with encryption, versioning, public access block, SSL-only bucket policy |
| `variables.tf` | Region, project name, S3 bucket name |
| `outputs.tf` | Group ARNs, role ARN, instance profile name, bucket ARN |

---

## 🚀 Deployment

```bash
cd terraform/unit2_iam
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

### Post-Deployment: Assign Users to Groups

```bash
# Add users to groups (done via AWS Console or CLI)
aws iam add-user-to-group --user-name alice --group-name csa-iam-admins
aws iam add-user-to-group --user-name bob --group-name csa-iam-developers
aws iam add-user-to-group --user-name carol --group-name csa-iam-auditors
```

### Post-Deployment: Launch EC2 with Instance Profile

```bash
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --instance-type t3.micro \
  --iam-instance-profile Name=csa-iam-ec2-s3-instance-profile \
  --metadata-options HttpTokens=required
```
