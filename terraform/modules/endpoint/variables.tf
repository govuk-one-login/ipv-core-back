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

variable "http_method" {
  type        = string
  description = "http request type"
}

variable "path_part" {
  type        = string
  description = "path part to register the new resource under"
}

variable "handler" {
  type        = string
  description = "Class handler for each of the lambdas"
}

variable "function_name" {
  type        = string
  description = "Lambda function name"
}

variable "role_name" {
  type        = string
  description = "Lambda iam role name"
}

variable "additional_policies" {
  type = list(string)
  description = "List of ARNs of IAM policies to attach to the lambda's execution role"
}

variable "user_issued_credentials_table_name" {
  type        = string
  default     = "not-set-for-this-lambda"
  description = "Name of the DynamoDB user-credentials table"
}

variable "auth_codes_table_name" {
  type        = string
  default     = "not-set-for-this-lambda"
  description = "Name of the DynamoDB auth-codes table"
}

variable "access_tokens_table_name" {
  type        = string
  default     = "not-set-for-this-lambda"
  description = "Name of the DynamoDB access-tokens table"
}

variable "ipv_sessions_table_name" {
  type        = string
  default     = "not-set-for-this-lambda"
  description = "Name of the DynamoDB ipv-sessions table"
}

variable "credential_issuer_config_parameter_store_key" {
  type        = string
  default     = null
  description = "Name of the credential issuer config parameter in the parameter store"
}

locals {
  default_tags = {
    Environment = var.environment
    Source      = "github.com/alphagov/di-ipv-core-back/terraform/lambda"
  }
}
