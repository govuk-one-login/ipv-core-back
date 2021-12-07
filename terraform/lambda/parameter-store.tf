resource "aws_ssm_parameter" "credential-issuers-config" {
  name  = "/${var.environment}/credential-issuers-config"
  type  = "String"
  value = var.credential_issuers_config
}
