resource "aws_ssm_parameter" "token_url" {
  for_each  = {for c in var.issuers : c.id => c}
  name      = "/${var.environment}/ipv/core/credentialIssuers/${each.value.id}/tokenUrl"
  type      = var.type
  value     = each.value.token_url
  overwrite = var.overwrite
}

resource "aws_ssm_parameter" "credential_url" {
  for_each  = {for c in var.issuers : c.id => c}
  name      = "/${var.environment}/ipv/core/credentialIssuers/${each.value.id}/credentialUrl"
  type      = var.type
  value     = each.value.credential_url
  overwrite = var.overwrite
}
