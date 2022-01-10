module "token" {
  source      = "../modules/endpoint"
  environment = var.environment

  rest_api_id            = aws_api_gateway_rest_api.ipv_internal.id
  rest_api_execution_arn = aws_api_gateway_rest_api.ipv_internal.execution_arn
  root_resource_id       = aws_api_gateway_rest_api.ipv_internal.root_resource_id
  http_method            = "POST"
  path_part              = "token"
  handler                = "uk.gov.di.ipv.core.accesstoken.AccessTokenHandler::handleRequest"
  function_name          = "${var.environment}-token"
  role_name              = "${var.environment}-token-role"

  allow_access_to_auth_codes_table = true
  auth_codes_table_policy_arn      = aws_iam_policy.policy-auth-codes-table.arn
  auth_codes_table_name            = aws_dynamodb_table.auth-codes.name

  allow_access_to_access_tokens_table = true
  access_tokens_table_policy_arn      = aws_iam_policy.policy-access-tokens-table.arn
  access_tokens_table_name            = aws_dynamodb_table.access-tokens.name
}
