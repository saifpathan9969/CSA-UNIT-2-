# ─────────────────────────────────────────────────────────────
# Unit 2 – IAM Least Privilege Architecture · Main
# ─────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = "pbl"
      ManagedBy   = "terraform"
    }
  }
}

# ──────────────────────────────────────────────────────────────
# Data: current AWS account ID
# ──────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
