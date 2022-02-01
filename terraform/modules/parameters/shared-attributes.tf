resource "aws_ssm_parameter" "shared_attributes_signing_cert" {
  name        = "/${var.environment}/ipv/core/sharedAttributes/signingCert"
  description = "The IPV core's shared attributes signing certificate"
  type        = "String"
  value       = var.shared_attributes_signing_cert
}

data "aws_kms_key" "shared_attributes_signing" {
  key_id = "alias/sharedAttributesSigning"
}

resource "aws_ssm_parameter" "shared_attributes_signing_key_id" {
  name        = "/${var.environment}/ipv/core/sharedAttributes/signingKeyId"
  description = "The IPV core's shared attributes KMS signing key ID"
  type        = "String"
  value       = data.aws_kms_key.shared_attributes_signing.key_id
}
