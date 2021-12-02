module "user-identity" {
  source      = "../modules/endpoint"
  environment = var.environment

  rest_api_id            = aws_api_gateway_rest_api.ipv_internal.id
  rest_api_execution_arn = aws_api_gateway_rest_api.ipv_internal.execution_arn
  root_resource_id       = aws_api_gateway_rest_api.ipv_internal.root_resource_id
  http_method            = "GET"
  path_part              = "user-identity"
  handler                = "uk.gov.di.ipv.lambda.UserInfoHandler::handleRequest"
  function_name          = "${var.environment}-user-identity"
  role_name              = "${var.environment}-user-identity-role"

  allow_access_to_user_issued_credentials_table = true
  user_issued_credentials_table_policy_arn      = aws_iam_policy.policy-user-issued-credentials-table.arn
  user_issued_credentials_table_name            = aws_dynamodb_table.user-issued-credentials.name

  allow_access_to_access_tokens_table = true
  access_tokens_table_policy_arn      = aws_iam_policy.policy-access-tokens-table.arn
  access_tokens_table_name            = aws_dynamodb_table.access-tokens.name
}
