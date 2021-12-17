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

resource "aws_iam_role_policy_attachment" "additional_policies" {
  for_each   = toset(var.additional_policies)
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = each.key
}
