variable "environment" {
  type = string
}

variable "use_localstack" {
  type    = bool
  default = false
}

variable "credential_issuers_config" {
  type        = string
  description = "Base64 encoded YAML config for credential issuers"
}

locals {
  default_tags = var.use_localstack ? null : {
    Environment = var.environment
    Source      = "github.com/alphagov/di-ipv-core-back/terraform/lambda"
  }
}
