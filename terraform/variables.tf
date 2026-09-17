# ─────────────────────────────────────────────────────────────
# Unit 2 – IAM Least Privilege Architecture · Variables
# ─────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "csa-iam"
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket for EC2 role demo"
  type        = string
  default     = "csa-pbl-app-data-bucket"
}
