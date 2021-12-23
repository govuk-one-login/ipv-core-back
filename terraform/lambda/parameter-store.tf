resource "aws_ssm_parameter" "credential-issuers-config" {
  name      = "/${var.environment}/credential-issuers-config"
  type      = "String"
  value     = var.credential_issuers_config
  overwrite = true
}

resource "aws_iam_role_policy" "get-credential-issuers-config" {
  name   = "get-credential-issuers-config"
  role   = module.credential-issuer.iam_role_id
  policy = data.aws_iam_policy_document.get_credential_issuers_config.json
}

data "aws_iam_policy_document" "get_credential_issuers_config" {
  statement {
    sid     = "GetCredentialIssuersConfig"
    effect  = "Allow"
    actions = ["ssm:GetParameter"]

    resources = [
      aws_ssm_parameter.credential-issuers-config.arn
    ]
  }
}
