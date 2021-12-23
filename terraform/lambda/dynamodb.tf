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

resource "aws_dynamodb_table" "ipv-sessions" {
  name         = "${var.environment}-ipv-sessions"
  hash_key     = "ipvSessionId"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "ipvSessionId"
    type = "S"
  }

  tags = local.default_tags
}

resource "aws_iam_policy" "policy-user-issued-credentials-table" {
  name   = "policy-user-issued-credentials-table"
  policy = data.aws_iam_policy_document.policy_user_issued_credentials_table_policy.json
}

data "aws_iam_policy_document" "policy_user_issued_credentials_table_policy" {
  statement {
    sid     = "PolicyUserIssuedCredentialsTable"
    effect  = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:GetItem",
      "dynamodb:BatchGetItem",
      "dynamodb:Scan",
      "dynamodb:Query",
      "dynamodb:ConditionCheckItem"
    ]

    resources = [
      aws_dynamodb_table.user-issued-credentials.arn,
      "${aws_dynamodb_table.user-issued-credentials.arn}/index/*"
    ]
  }
}

resource "aws_iam_policy" "policy-auth-codes-table" {
  name   = "policy-auth-codes-table"
  policy = data.aws_iam_policy_document.policy_auth_codes_table_policy.json
}

data "aws_iam_policy_document" "policy_auth_codes_table_policy" {
  statement {
    sid     = "PolicyAuthCodesTable"
    effect  = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query"
    ]

    resources = [
      aws_dynamodb_table.auth-codes.arn,
      "${aws_dynamodb_table.auth-codes.arn}/index/*"
    ]
  }
}

resource "aws_iam_policy" "policy-access-tokens-table" {
  name   = "policy-access-tokens-table"
  policy = data.aws_iam_policy_document.access_tokens_table_policy.json
}

data "aws_iam_policy_document" "access_tokens_table_policy" {
  statement {
    sid     = "AccessTokensTable"
    effect  = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query"
    ]

    resources = [
      aws_dynamodb_table.access-tokens.arn,
      "${aws_dynamodb_table.access-tokens.arn}/index/*"
    ]
  }
}

resource "aws_iam_policy" "policy-ipv-sessions-table" {
  name   = "policy-ipv-sessions-table"
  policy = data.aws_iam_policy_document.ipv_sessions_table_policy.json
}

data "aws_iam_policy_document" "ipv_sessions_table_policy" {
  statement {
    sid     = "IpvSessionsTable"
    effect  = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query"
    ]

    resources = [
      aws_dynamodb_table.ipv-sessions.arn,
      "${aws_dynamodb_table.ipv-sessions.arn}/index/*"
    ]
  }
}
