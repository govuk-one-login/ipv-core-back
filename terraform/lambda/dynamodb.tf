resource "aws_dynamodb_table" "user-credentials-table" {
  name         = "user-credentials-table"
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

resource "aws_iam_policy" "dynamo-db-user-credentials-table-policy" {
  name = "dynamo-db-user-credentials-table-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AllowDynamoDbReadWrite"
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
          aws_dynamodb_table.user-credentials-table.arn,
          "${aws_dynamodb_table.user-credentials-table.arn}/index/*"
        ]
      },
    ]
  })
}
