variable "environment" {
  description = "Name of the environment this is being created in"
  type        = string
}

variable "issuers_config" {
  description = "Map of credential issuers configuration to store in Parameter Store"
  type        = map(any)
}
