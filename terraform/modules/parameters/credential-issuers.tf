resource "aws_ssm_parameter" "id" {
  for_each  = { for c in var.issuers : c.id => c }
  name      = "/${var.environment}/ipv/core/credentialIssuers/${each.value.id}/id"
  type      = var.type
  value     = each.value.id
  overwrite = var.overwrite
}

resource "aws_ssm_parameter" "name" {
  for_each  = { for c in var.issuers : c.id => c }
  name      = "/${var.environment}/ipv/core/credentialIssuers/${each.value.id}/name"
  type      = var.type
  value     = each.value.name
  overwrite = var.overwrite
}

resource "aws_ssm_parameter" "authorize_url" {
  for_each  = { for c in var.issuers : c.id => c }
  name      = "/${var.environment}/ipv/core/credentialIssuers/${each.value.id}/authorizeUrl"
  type      = var.type
  value     = each.value.authorizeUrl
  overwrite = var.overwrite
}

resource "aws_ssm_parameter" "token_url" {
  for_each  = { for c in var.issuers : c.id => c }
  name      = "/${var.environment}/ipv/core/credentialIssuers/${each.value.id}/tokenUrl"
  type      = var.type
  value     = each.value.tokenUrl
  overwrite = var.overwrite
}

resource "aws_ssm_parameter" "credential_url" {
  for_each  = { for c in var.issuers : c.id => c }
  name      = "/${var.environment}/ipv/core/credentialIssuers/${each.value.id}/credentialUrl"
  type      = var.type
  value     = each.value.credentialUrl
  overwrite = var.overwrite
}

// Tempory until we move to SAM
resource "aws_iam_policy" "credential_issuers_config" {
  name   = "${var.environment}-get-credential-issuers-config"
  policy = data.aws_iam_policy_document.credential_issuers_config.json
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "credential_issuers_config" {
  statement {
    sid    = "AllowLambdaParameterStore"
    effect = "Allow"

    actions = [
      "ssm:GetParameter",
      "ssm:GetParametersByPath"
    ]

    resources = [
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${var.environment}/ipv/core/credentialIssuers/*",
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${var.environment}/ipv/core/credentialIssuers"
    ]
  }
}
