resource "aws_dynamodb_table" "user-issued-credentials" {
  name         = "${var.environment}-user-issued-credentials"
  hash_key     = "ipvSessionId"
  range_key    = "credentialIssuer"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "ipvSessionId"
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
  hash_key     = "authCode"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "authCode"
    type = "S"
  }

  tags = local.default_tags
}

resource "aws_dynamodb_table" "access-tokens" {
  name         = "${var.environment}-access-tokens"
  hash_key     = "accessToken"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "accessToken"
    type = "S"
  }

  tags = local.default_tags
}

resource "aws_iam_policy" "policy-user-issued-credentials-table" {
  name = "policy-user-issued-credentials-table"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "PolicyUserIssuedCredentialsTable"
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

resource "aws_iam_policy" "policy-auth-codes-table" {
  name = "policy-auth-codes-table"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "PolicyAuthCodesTable"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query"
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

resource "aws_iam_policy" "policy-access-tokens-table" {
  name = "policy-access-tokens-table"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AccessTokensTable"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query"
        ]
        Effect = "Allow"
        Resource = [
          aws_dynamodb_table.access-tokens.arn,
          "${aws_dynamodb_table.access-tokens.arn}/index/*"
        ]
      },
    ]
  })
}
