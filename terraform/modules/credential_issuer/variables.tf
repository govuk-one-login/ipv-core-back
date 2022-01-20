variable "issuers" {
  description = "Credential issuers configuration to store in Parameter Store"
}

variable "environment" {
  description = "Name of the environment this is being created in"
  type        = string
}

variable "overwrite" {
  description = "Overwrite the value already stored inside of Parameter Store"
  default     = true
  type        = bool
}

variable "type" {
  description = "Type of value to store in Parameter Store"
  default     = "String"
  type        = string
}


output "credential_issuers_iam_policy_arn" {
  value = aws_iam_policy.credential_issuers_config.arn
}
