# ─────────────────────────────────────────────────────────────
# Unit 2 – IAM Groups & Policies (Least Privilege + MFA)
# Groups: Admins, Developers, Auditors
# ─────────────────────────────────────────────────────────────

# ══════════════════════════════════════════════════════════════
# 1. IAM GROUPS
# ══════════════════════════════════════════════════════════════

resource "aws_iam_group" "admins" {
  name = "${var.project_name}-admins"
  path = "/csa/"
}

resource "aws_iam_group" "developers" {
  name = "${var.project_name}-developers"
  path = "/csa/"
}

resource "aws_iam_group" "auditors" {
  name = "${var.project_name}-auditors"
  path = "/csa/"
}

# ══════════════════════════════════════════════════════════════
# 2. MFA ENFORCEMENT POLICY (Applied to ALL groups)
# ══════════════════════════════════════════════════════════════
# Logic: Deny ALL actions EXCEPT self-service MFA management
# unless the user has authenticated with MFA in the current
# session. This ensures no AWS API call can be made without MFA.

resource "aws_iam_policy" "enforce_mfa" {
  name        = "${var.project_name}-enforce-mfa"
  path        = "/csa/"
  description = "Deny all actions unless MFA is active; allow self-service MFA setup"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowViewAccountInfo"
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:ListVirtualMFADevices"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowManageOwnMFA"
        Effect = "Allow"
        Action = [
          "iam:CreateVirtualMFADevice",
          "iam:DeleteVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ResyncMFADevice",
          "iam:ListMFADevices",
          "iam:DeactivateMFADevice"
        ]
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:mfa/$${aws:username}",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/$${aws:username}"
        ]
      },
      {
        Sid    = "AllowManageOwnPasswords"
        Effect = "Allow"
        Action = [
          "iam:ChangePassword",
          "iam:GetUser"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/$${aws:username}"
      },
      {
        Sid       = "DenyAllExceptMFASetupWithoutMFA"
        Effect    = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ChangePassword",
          "iam:GetAccountPasswordPolicy",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

# Attach MFA enforcement to all groups
resource "aws_iam_group_policy_attachment" "admins_mfa" {
  group      = aws_iam_group.admins.name
  policy_arn = aws_iam_policy.enforce_mfa.arn
}

resource "aws_iam_group_policy_attachment" "developers_mfa" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.enforce_mfa.arn
}

resource "aws_iam_group_policy_attachment" "auditors_mfa" {
  group      = aws_iam_group.auditors.name
  policy_arn = aws_iam_policy.enforce_mfa.arn
}

# ══════════════════════════════════════════════════════════════
# 3. ADMIN GROUP POLICY
# ══════════════════════════════════════════════════════════════
# Full admin access – MFA enforcement above ensures this can
# only be exercised after MFA authentication.

resource "aws_iam_group_policy_attachment" "admins_full" {
  group      = aws_iam_group.admins.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ══════════════════════════════════════════════════════════════
# 4. DEVELOPER GROUP POLICY (Least Privilege)
# ══════════════════════════════════════════════════════════════
# Restricted to: EC2, S3, CloudWatch, CloudFormation
# Denied: IAM admin, Billing, Organizations, account changes

resource "aws_iam_policy" "developer_access" {
  name        = "${var.project_name}-developer-access"
  path        = "/csa/"
  description = "Developer least-privilege: EC2, S3, CloudWatch, CloudFormation"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2FullForDev"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:RunInstances",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:RebootInstances",
          "ec2:TerminateInstances",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:CreateSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:DeleteSecurityGroup",
          "ec2:CreateKeyPair",
          "ec2:DeleteKeyPair"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.aws_region
          }
        }
      },
      {
        Sid    = "S3Access"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation"
        ]
        Resource = [
          "arn:aws:s3:::${var.s3_bucket_name}",
          "arn:aws:s3:::${var.s3_bucket_name}/*"
        ]
      },
      {
        Sid    = "CloudWatchAccess"
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics",
          "cloudwatch:PutMetricData",
          "cloudwatch:DescribeAlarms",
          "logs:GetLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents",
          "logs:CreateLogGroup",
          "logs:CreateLogStream"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyIAMAndBilling"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:CreateGroup",
          "iam:DeleteGroup",
          "iam:AttachUserPolicy",
          "iam:AttachGroupPolicy",
          "iam:PutUserPolicy",
          "iam:PutGroupPolicy",
          "iam:CreateRole",
          "iam:DeleteRole",
          "organizations:*",
          "account:*",
          "aws-portal:*",
          "budgets:*",
          "cur:*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_group_policy_attachment" "developers_access" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.developer_access.arn
}

# ══════════════════════════════════════════════════════════════
# 5. AUDITOR GROUP POLICY (Read-Only Security)
# ══════════════════════════════════════════════════════════════

resource "aws_iam_group_policy_attachment" "auditors_security_audit" {
  group      = aws_iam_group.auditors.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_policy" "auditor_readonly" {
  name        = "${var.project_name}-auditor-readonly"
  path        = "/csa/"
  description = "Auditor read-only: CloudTrail, AWS Config, GuardDuty, Shield"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudTrailReadOnly"
        Effect = "Allow"
        Action = [
          "cloudtrail:GetTrailStatus",
          "cloudtrail:DescribeTrails",
          "cloudtrail:LookupEvents",
          "cloudtrail:GetEventSelectors",
          "cloudtrail:ListTrails"
        ]
        Resource = "*"
      },
      {
        Sid    = "ConfigReadOnly"
        Effect = "Allow"
        Action = [
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "config:BatchGetResourceConfig"
        ]
        Resource = "*"
      },
      {
        Sid    = "GuardDutyReadOnly"
        Effect = "Allow"
        Action = [
          "guardduty:Get*",
          "guardduty:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ShieldAndWAFReadOnly"
        Effect = "Allow"
        Action = [
          "shield:Describe*",
          "shield:List*",
          "waf:Get*",
          "waf:List*",
          "wafv2:Get*",
          "wafv2:List*",
          "wafv2:Describe*"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyWriteActions"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:StopInstances",
          "ec2:StartInstances",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:DeleteBucket",
          "iam:Create*",
          "iam:Delete*",
          "iam:Put*",
          "iam:Attach*",
          "iam:Detach*",
          "iam:Update*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_group_policy_attachment" "auditors_readonly" {
  group      = aws_iam_group.auditors.name
  policy_arn = aws_iam_policy.auditor_readonly.arn
}
