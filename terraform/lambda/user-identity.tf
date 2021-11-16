module "user-identity" {
  source      = "../modules/endpoint"
  environment = var.environment

  rest_api_id            = aws_api_gateway_rest_api.ipv_internal.id
  rest_api_execution_arn = aws_api_gateway_rest_api.ipv_internal.execution_arn
  root_resource_id       = aws_api_gateway_rest_api.ipv_internal.root_resource_id
  path_part              = "user-identity"
  handler                = "uk.gov.di.ipv.lambda.UserInfoHandler::handleRequest"
  function_name          = "${var.environment}-user-identity"
  role_name              = "${var.environment}-user-identity-role"
}
