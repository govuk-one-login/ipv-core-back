resource "aws_api_gateway_rest_api" "ipv_internal" {
  name = "${var.environment}-ipv-internal"

  tags = local.default_tags
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
  source_code_hash = filebase64sha256(var.lambda_zip_file)
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


resource "aws_api_gateway_resource" "endpoint_resource" {
  rest_api_id = aws_api_gateway_rest_api.ipv_internal.id
  parent_id   = aws_api_gateway_rest_api.ipv_internal.root_resource_id
  path_part   = "hello"
}

resource "aws_api_gateway_method" "endpoint_method" {
  rest_api_id = aws_api_gateway_rest_api.ipv_internal.id
  resource_id = aws_api_gateway_resource.endpoint_resource.parent_id
  http_method = "GET"
  authorization = "NONE"
  api_key_required   = false
}

resource "aws_api_gateway_integration" "endpoint_integration" {
  rest_api_id        = aws_api_gateway_rest_api.ipv_internal.id
  resource_id        = aws_api_gateway_rest_api.ipv_internal.root_resource_id
  http_method        = aws_api_gateway_method.endpoint_method.http_method

  integration_http_method = "POST"
  type                    = "AWS"
  uri                     = aws_lambda_alias.authorize_active.invoke_arn
}


resource "aws_api_gateway_method_response" "response_200" {
  rest_api_id = aws_api_gateway_rest_api.ipv_internal.id
  resource_id = aws_api_gateway_rest_api.ipv_internal.root_resource_id
  http_method = aws_api_gateway_method.endpoint_method.http_method
  status_code = "200"
}

resource "aws_api_gateway_integration_response" "endpoint_integration_response" {
  rest_api_id = aws_api_gateway_rest_api.ipv_internal.id
  resource_id = aws_api_gateway_rest_api.ipv_internal.root_resource_id
  http_method = aws_api_gateway_method.endpoint_method.http_method
  status_code = aws_api_gateway_method_response.response_200.status_code

}


resource "aws_lambda_permission" "endpoint_execution_base_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorize.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn = "${aws_api_gateway_rest_api.ipv_internal.execution_arn}/*/*/"

}

resource "aws_lambda_permission" "endpoint_execution_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorize.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = aws_lambda_alias.authorize_active.name

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
#  source_arn = "${var.execution_arn}/*/*"


  source_arn = "${aws_api_gateway_rest_api.ipv_internal.execution_arn}/*/*/"

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
