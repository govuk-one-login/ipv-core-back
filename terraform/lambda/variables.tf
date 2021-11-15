variable "environment" {
  type = string
}

variable "use_localstack" {
  type = bool
  default = false
}

variable "lambda_zip_file" {
  default     = "../../../../di-ipv-core-back/build/distributions/di-ipv-core-back.zip"
  description = "Location of the Lambda ZIP file"
  type        = string
}

locals {
  default_tags = var.use_localstack ? null : {
    Environment = var.environment
    Source      = "github.com/alphagov/di-ipv-core-back/terraform/lambda"
  }
}
