# ─────────────────────────────────────────────────────────────
# Unit 2 – S3 Bucket (Encrypted, Private, SSL-Only)
# ─────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "app_data" {
  bucket        = var.s3_bucket_name
  force_destroy = true

  tags = { Name = "${var.project_name}-app-data" }
}

# ── Block all public access ─────────────────────────────────
resource "aws_s3_bucket_public_access_block" "app_data" {
  bucket = aws_s3_bucket.app_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── Server-side encryption (AES-256 / SSE-S3) ──────────────
resource "aws_s3_bucket_server_side_encryption_configuration" "app_data" {
  bucket = aws_s3_bucket.app_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# ── Versioning ──────────────────────────────────────────────
resource "aws_s3_bucket_versioning" "app_data" {
  bucket = aws_s3_bucket.app_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ── Bucket Policy: Enforce SSL/TLS only ─────────────────────
resource "aws_s3_bucket_policy" "enforce_ssl" {
  bucket = aws_s3_bucket.app_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::${var.s3_bucket_name}",
          "arn:aws:s3:::${var.s3_bucket_name}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.app_data]
}
