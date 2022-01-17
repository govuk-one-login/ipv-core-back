variable "issuers" {
  description = "Map of credential issuers configuration to store in Parameter Store"
  type        = list(map(string))
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
