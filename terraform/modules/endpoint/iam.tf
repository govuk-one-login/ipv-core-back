data "aws_iam_policy_document" "lambda_can_assume_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    principals {
      identifiers = [
        "lambda.amazonaws.com"
      ]
      type = "Service"
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_iam_role" "lambda_iam_role" {
  name = var.role_name

  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_policy.json

  tags = local.default_tags
}

resource "aws_iam_role_policy_attachment" "user_issued_credentials_table_policy_to_lambda_iam_role" {
  count      = var.allow_access_to_user_issued_credentials_table ? 1 : 0
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = var.user_issued_credentials_table_policy_arn
}

resource "aws_iam_role_policy_attachment" "auth_codes_table_policy_to_lambda_iam_role" {
  count      = var.allow_access_to_auth_codes_table ? 1 : 0
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = var.auth_codes_table_policy_arn
}
