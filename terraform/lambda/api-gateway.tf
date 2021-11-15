resource "aws_api_gateway_rest_api" "ipv_internal" {
  name        = "${var.environment}-ipv-internal"
  description = "The api accessed by internal IPV systems, e.g. di-ipv-core-front"
  tags        = local.default_tags
}

data "archive_file" "dummy" {
  type        = "zip"
  output_path = "${path.module}/lambda_function_payload.zip"

  source {
    content   = "hello"
    filename  = "dummy.txt"
  }
}

resource "aws_lambda_function" "authorize" {
  filename         = data.archive_file.dummy.output_path
  function_name    = "${var.environment}-authorize"
  role             = aws_iam_role.lambda_iam_role.arn
  handler          = "uk.gov.di.ipv.lambda.AuthorizationHandler::handleRequest"
  runtime          = "java11"
  source_code_hash = filebase64sha256(data.archive_file.dummy.output_path)
  publish          = false
  timeout          = 30
  memory_size      = 2048

  # There is an outstanding bug in terraform (Issue #3630) that means it always tries to update the
  # last modified date, even if no other attributes in the lambda need changing
  lifecycle {
    ignore_changes = [last_modified, filename]
  }
}

resource "aws_lambda_alias" "authorize_active" {
  name             = "${var.environment}-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.authorize.arn
  function_version = aws_lambda_function.authorize.version
}


resource "aws_api_gateway_resource" "authorize_endpoint" {
  rest_api_id = aws_api_gateway_rest_api.ipv_internal.id
  parent_id   = aws_api_gateway_rest_api.ipv_internal.root_resource_id
  path_part   = "authorize"
}

resource "aws_api_gateway_method" "authorize_endpoint_method" {
  rest_api_id = aws_api_gateway_rest_api.ipv_internal.id
  resource_id = aws_api_gateway_resource.authorize_endpoint.id
  http_method = "GET"
  authorization = "NONE"
  api_key_required   = false
}

resource "aws_api_gateway_integration" "endpoint_integration" {
  rest_api_id        = aws_api_gateway_rest_api.ipv_internal.id
  resource_id        = aws_api_gateway_resource.authorize_endpoint.id
  http_method        = aws_api_gateway_method.authorize_endpoint_method.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_alias.authorize_active.invoke_arn
}

resource "aws_lambda_permission" "endpoint_execution_base_permission" {
  statement_id  = "AllowAPIGatewayInvokeBase"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorize.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn = "${aws_api_gateway_rest_api.ipv_internal.execution_arn}/*/*/authorize"
}

resource "aws_lambda_permission" "endpoint_execution_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorize.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = aws_lambda_alias.authorize_active.name
  source_arn = "${aws_api_gateway_rest_api.ipv_internal.execution_arn}/*/*/authorize"
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.ipv_internal.id

  triggers = {
    redeployment = sha1(jsonencode(aws_api_gateway_integration.endpoint_integration))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "endpoint_stage" {
  deployment_id = aws_api_gateway_deployment.deployment.id
  rest_api_id   = aws_api_gateway_rest_api.ipv_internal.id
  stage_name    = var.environment
}
