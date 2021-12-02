variable "environment" {
  type = string
}

variable "use_localstack" {
  type    = bool
  default = false
}

variable "credential_issuer_config" {
  type = string
  default = null
  description = "Base64 encoded YAML credential issuer config"
}

locals {
  default_tags = var.use_localstack ? null : {
    Environment = var.environment
    Source      = "github.com/alphagov/di-ipv-core-back/terraform/lambda"
  }
}
