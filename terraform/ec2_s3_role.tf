# ─────────────────────────────────────────────────────────────
# Unit 2 – EC2-to-S3 IAM Role (Credential-less Access)
# No hardcoded AWS keys – uses IAM Instance Profile + IMDSv2
# ─────────────────────────────────────────────────────────────

# ══════════════════════════════════════════════════════════════
# 1. IAM Role – Trust Policy for EC2 Service
# ══════════════════════════════════════════════════════════════

resource "aws_iam_role" "ec2_s3_role" {
  name = "${var.project_name}-ec2-s3-role"
  path = "/csa/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EC2AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = { Name = "${var.project_name}-ec2-s3-role" }
}

# ══════════════════════════════════════════════════════════════
# 2. IAM Policy – Least-Privilege S3 Access
# ══════════════════════════════════════════════════════════════

resource "aws_iam_policy" "ec2_s3_access" {
  name        = "${var.project_name}-ec2-s3-access"
  path        = "/csa/"
  description = "Allows EC2 to read/write objects in the app data S3 bucket only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = "arn:aws:s3:::${var.s3_bucket_name}"
      },
      {
        Sid    = "ReadWriteObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "arn:aws:s3:::${var.s3_bucket_name}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_s3" {
  role       = aws_iam_role.ec2_s3_role.name
  policy_arn = aws_iam_policy.ec2_s3_access.arn
}

# ══════════════════════════════════════════════════════════════
# 3. Instance Profile (attaches Role to EC2 instances)
# ══════════════════════════════════════════════════════════════

resource "aws_iam_instance_profile" "ec2_s3_profile" {
  name = "${var.project_name}-ec2-s3-instance-profile"
  role = aws_iam_role.ec2_s3_role.name

  tags = { Name = "${var.project_name}-ec2-s3-instance-profile" }
}
