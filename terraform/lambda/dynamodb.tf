resource "aws_dynamodb_table" "user-issued-credentials" {
  name         = "${var.environment}-user-issued-credentials"
  hash_key     = "sessionId"
  range_key    = "credentialIssuer"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "sessionId"
    type = "S"
  }

  attribute {
    name = "credentialIssuer"
    type = "S"
  }

  tags = local.default_tags
}

resource "aws_dynamodb_table" "auth-codes" {
  name         = "${var.environment}-auth-codes"
  hash_key     = "sessionId"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "sessionId"
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

resource "aws_iam_policy" "access-auth-codes-table" {
  name = "access-auth-codes-table"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AccessAuthCodesTable"
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
          aws_dynamodb_table.auth-codes.arn,
          "${aws_dynamodb_table.auth-codes.arn}/index/*"
        ]
      },
    ]
  })
}
