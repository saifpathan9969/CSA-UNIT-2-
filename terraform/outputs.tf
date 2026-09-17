# ─────────────────────────────────────────────────────────────
# Unit 2 – IAM Least Privilege Architecture · Outputs
# ─────────────────────────────────────────────────────────────

output "admin_group_arn" {
  description = "ARN of the Admins IAM group"
  value       = aws_iam_group.admins.arn
}

output "developer_group_arn" {
  description = "ARN of the Developers IAM group"
  value       = aws_iam_group.developers.arn
}

output "auditor_group_arn" {
  description = "ARN of the Auditors IAM group"
  value       = aws_iam_group.auditors.arn
}

output "mfa_enforcement_policy_arn" {
  description = "ARN of the MFA enforcement policy"
  value       = aws_iam_policy.enforce_mfa.arn
}

output "ec2_s3_role_arn" {
  description = "ARN of the EC2-to-S3 IAM role"
  value       = aws_iam_role.ec2_s3_role.arn
}

output "ec2_s3_instance_profile_name" {
  description = "Name of the EC2 instance profile for S3 access"
  value       = aws_iam_instance_profile.ec2_s3_profile.name
}

output "s3_bucket_arn" {
  description = "ARN of the app data S3 bucket"
  value       = aws_s3_bucket.app_data.arn
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket"
  value       = aws_s3_bucket.app_data.id
}
