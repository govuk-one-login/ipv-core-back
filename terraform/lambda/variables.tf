variable "environment" {
  type = string
}

variable "use_localstack" {
  type    = bool
  default = false
}

locals {
  default_tags = var.use_localstack ? null : {
    Environment = var.environment
    Source      = "github.com/alphagov/di-ipv-core-back/terraform/lambda"
  }
}
