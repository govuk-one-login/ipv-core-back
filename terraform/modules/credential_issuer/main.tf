resource "aws_ssm_parameter" "token_url" {
  for_each  = {for c in var.issuers : c.id => c}
  name      = "/${var.environment}/ipv/core/credentialIssuers/${each.value.id}/tokenUrl"
  type      = var.type
  value     = each.value.tokenUrl
  overwrite = var.overwrite
}

resource "aws_ssm_parameter" "credential_url" {
  for_each  = {for c in var.issuers : c.id => c}
  name      = "/${var.environment}/ipv/core/credentialIssuers/${each.value.id}/credentialUrl"
  type      = var.type
  value     = each.value.credentialUrl
  overwrite = var.overwrite
}

// Tempory until we move to SAM
resource "aws_iam_role_policy" "credential_issuers_config" {
  name_prefix = "${var.environment}-get-credential-issuers-config-"
  role       = var.credential_issuer_iam_role
  policy     = data.aws_iam_policy_document.credential_issuers_config.json
}

data "aws_iam_policy_document" "credential_issuers_config" {
  statement {
    sid    = "AllowLambdaParameterStore"
    effect = "Allow"

    actions = [
      "ssm:GetParameter",
      "ssm:GetParametersByPath"
    ]

    resources = [
      aws_ssm_parameter.token_url.*.arn,
      aws_ssm_parameter.credential_url.*.arn
    ]
  }
}
