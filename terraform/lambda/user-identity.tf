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

  allow_access_to_user_credentials_table     = true
  dynamodb_user_credentials_table_policy_arn = aws_iam_policy.dynamo-db-user-credentials-table-policy.arn
  dynamodb_user_credentials_table_name       = aws_dynamodb_table.user-credentials-table.name
}
