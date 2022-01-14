module "credential-issuer-config" {
  source      = "../modules/endpoint"
  environment = var.environment

  rest_api_id            = aws_api_gateway_rest_api.ipv_internal.id
  rest_api_execution_arn = aws_api_gateway_rest_api.ipv_internal.execution_arn
  root_resource_id       = aws_api_gateway_rest_api.ipv_internal.root_resource_id
  http_method            = "GET"
  path_part              = "request-config"
  handler                = "uk.gov.di.ipv.core.credentialissuerconfig.credentialIssuerConfigHandler::handleRequest"
  function_name          = "${var.environment}-credential-issuer-config"
  role_name              = "${var.environment}-credential-issuer-config-role"

}
