output "trigger" {
  description = "arbitrary value which changes when the deployment needs to be retriggered"

  value = sha1(jsonencode(aws_api_gateway_integration.endpoint_integration))
}
