variable "environment" {
  type = string
}

variable "lambda_zip_file" {
  default     = "../../../../di-ipv-core-back/build/distributions/di-ipv-core-back.zip"
  description = "Location of the Lambda ZIP file"
  type        = string
}

locals {
  default_tags = {
    Environment = var.environment
    Source      = "github.com/alphagov/di-ipv-core-back/terraform/lambda"
  }
}
