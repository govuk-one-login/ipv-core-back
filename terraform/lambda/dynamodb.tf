resource "aws_dynamodb_table" "user-issued-credentials" {
  name         = "${var.environment}-user-issued-credentials"
  hash_key     = "SessionId"
  range_key    = "CredentialIssuer"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "SessionId"
    type = "S"
  }

  attribute {
    name = "CredentialIssuer"
    type = "S"
  }

  tags = local.default_tags
}

resource "aws_iam_policy" "access-user-issued-credentials-table" {
  name = "access-user-issued-credentials-table"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AccessUserIssuedCredentialsTable"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:GetItem",
          "dynamodb:BatchGetItem",
          "dynamodb:Scan",
          "dynamodb:Query",
          "dynamodb:ConditionCheckItem"
        ]
        Effect = "Allow"
        Resource = [
          aws_dynamodb_table.user-issued-credentials.arn,
          "${aws_dynamodb_table.user-issued-credentials.arn}/index/*"
        ]
      },
    ]
  })
}
