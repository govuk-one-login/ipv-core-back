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

variable "allow_access_to_user_issued_credentials_table" {
  type        = bool
  default     = false
  description = "Should the lambda be given access to the user-credentials DynamoDB table"
}

variable "user_issued_credentials_table_policy_arn" {
  type        = string
  default     = null
  description = "ARN of the policy to allow read write to the user-credentials DynamoDB table"
}

variable "user_issued_credentials_table_name" {
  type        = string
  default     = "not-set-for-this-lambda"
  description = "Name of the DynamoDB user-credentials table"
}

variable "allow_access_to_auth_codes_table" {
  type        = bool
  default     = false
  description = "Should the lambda be given access to the auth-codes DynamoDB table"
}

variable "auth_codes_table_policy_arn" {
  type        = string
  default     = null
  description = "ARN of the policy to allow read write to the auth-codes DynamoDB table"
}

variable "auth_codes_table_name" {
  type        = string
  default     = "not-set-for-this-lambda"
  description = "Name of the DynamoDB auth-codes table"
}

variable "allow_access_to_access_tokens_table" {
  type        = bool
  default     = false
  description = "Should the lambda be given access to the access-tokens DynamoDB table"
}

variable "access_tokens_table_policy_arn" {
  type        = string
  default     = null
  description = "ARN of the policy to allow read write to the access-tokens DynamoDB table"
}

variable "access_tokens_table_name" {
  type        = string
  default     = "not-set-for-this-lambda"
  description = "Name of the DynamoDB access-tokens table"
}

variable "allow_access_to_ipv_sessions_table" {
  type        = bool
  default     = false
  description = "Should the lambda be given access to the ipv-sessions DynamoDB table"
}

variable "ipv_sessions_table_policy_arn" {
  type        = string
  default     = null
  description = "ARN of the policy to allow read write to the ipv-sessions DynamoDB table"
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

variable "allow_access_to_credential_issuers_config" {
  type        = bool
  default     = true
  description = "Allow access to parameter store configuration"
}

variable "credential_issuers_iam_policy_arn" {
  description = "Credential Issuer Config IAM Policy ARN"
}

locals {
  default_tags = {
    Environment = var.environment
    Source      = "github.com/alphagov/di-ipv-core-back/terraform/lambda"
  }
}
