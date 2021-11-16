variable "environment" {
  type = string
}

variable "rest_api_id" {
  type        = string
  description = "id of the API Gateway REST API to register the lambda with"
}

variable "rest_api_execution_arn" {
  type        = string
  description = "ARN of the API Gateway REST API execution role"
}

variable "root_resource_id" {
  type        = string
  description = "id of the root resource within the REST API to register the lambda with"
}

variable "path_part" {
  type        = string
  description = "path part to register the new resource under"
}

variable "handler" {
  type       = string
  description = "Class handler for each of the lambdas"
}

variable "function_name" {
  type       = string
  description = "Lambda function name"
}

variable "role_name" {
  type       = string
  description = "Lambda iam role name"
}

locals {
  default_tags = {
    Environment = var.environment
    Source      = "github.com/alphagov/di-ipv-core-back/terraform/lambda"
  }
}
