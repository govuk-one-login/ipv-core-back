data "archive_file" "dummy" {
  type        = "zip"
  output_path = "${path.module}/lambda_function_payload.zip"

  source {
    content  = "hello"
    filename = "dummy.txt"
  }
}

data "aws_iam_policy_document" "lambda_can_assume_policy" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    principals {
      identifiers = [
        "lambda.amazonaws.com"
      ]
      type = "Service"
    }

    actions = [
      "sts:AssumeRole"
    ]
  }
}

resource "aws_iam_role" "lambda_iam_role" {
  name = "${var.environment}-lambda-role"

  assume_role_policy = data.aws_iam_policy_document.lambda_can_assume_policy.json

  tags = local.default_tags
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
  name             = "active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.authorize.arn
  function_version = aws_lambda_function.authorize.version
}


resource "aws_api_gateway_resource" "authorize_endpoint" {
  rest_api_id = var.rest_api_id
  parent_id   = var.root_resource_id
  path_part   = var.path_part
}

resource "aws_api_gateway_method" "authorize_endpoint_method" {
  rest_api_id      = var.rest_api_id
  resource_id      = aws_api_gateway_resource.authorize_endpoint.id
  http_method      = "GET"
  authorization    = "NONE"
  api_key_required = false
}

resource "aws_api_gateway_integration" "endpoint_integration" {
  rest_api_id = var.rest_api_id
  resource_id = aws_api_gateway_resource.authorize_endpoint.id
  http_method = aws_api_gateway_method.authorize_endpoint_method.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_alias.authorize_active.invoke_arn
}

resource "aws_lambda_permission" "endpoint_execution_base_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorize.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.rest_api_execution_arn}/*/${aws_api_gateway_method.authorize_endpoint_method.http_method}/${var.path_part}"
}

resource "aws_lambda_permission" "endpoint_execution_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorize.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = aws_lambda_alias.authorize_active.name
  source_arn    = "${var.rest_api_execution_arn}/*/${aws_api_gateway_method.authorize_endpoint_method.http_method}/${var.path_part}"

}
