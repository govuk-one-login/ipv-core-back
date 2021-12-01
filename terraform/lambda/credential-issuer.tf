module "credential-issuer" {
  source      = "../modules/endpoint"
  environment = var.environment

  rest_api_id            = aws_api_gateway_rest_api.ipv_internal.id
  rest_api_execution_arn = aws_api_gateway_rest_api.ipv_internal.execution_arn
  root_resource_id       = aws_api_gateway_rest_api.ipv_internal.root_resource_id
  http_method            = "POST"
  path_part              = "request-evidence"
  handler                = "uk.gov.di.ipv.lambda.CredentialIssuerHandler::handleRequest"
  function_name          = "${var.environment}-credential-issuer"
  role_name              = "${var.environment}-credential-issuer-role"

  allow_access_to_user_issued_credentials_table = true
  user_issued_credentials_table_policy_arn      = aws_iam_policy.access-user-issued-credentials-table.arn
  user_issued_credentials_table_name            = aws_dynamodb_table.user-issued-credentials.name
}
