output "trigger" {
  description = "arbitrary value which changes when the deployment needs to be retriggered"
  value       = sha1(jsonencode(aws_api_gateway_integration.endpoint_integration))
}

output "iam_role_id" {
  description = "The ID of the IAM role used by the lambda"
  value       = aws_iam_role.lambda_iam_role.id
}
