resource "aws_iam_role" "example" {
  name = "example-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "*"
        }
      }
    ]
  })
}


resource "s3_bucket" "insecure_bucket" {
  bucket = "insecure-bucket"
  acl    = "public-read"
}
