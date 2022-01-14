module "credential_issuers_config" {
  source      = "./modules/credential_issuer"
  environment = var.environment
  issuers     = var.issuers_config
}
