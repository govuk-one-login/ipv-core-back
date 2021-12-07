data "archive_file" "dummy" {
  type        = "zip"
  output_path = "${path.module}/lambda_function_payload.zip"

  source {
    content  = "hello"
    filename = "dummy.txt"
  }
}

resource "aws_lambda_function" "lambda_function" {
  filename         = data.archive_file.dummy.output_path
  function_name    = var.function_name
  role             = aws_iam_role.lambda_iam_role.arn
  handler          = var.handler
  runtime          = "java11"
  source_code_hash = filebase64sha256(data.archive_file.dummy.output_path)
  publish          = false
  timeout          = 30
  memory_size      = 2048

  environment {
    variables = {
      USER_ISSUED_CREDENTIALS_TABLE_NAME = var.user_issued_credentials_table_name
      AUTH_CODES_TABLE_NAME = var.auth_codes_table_name
      ACCESS_TOKENS_TABLE_NAME = var.access_tokens_table_name
      IPV_SESSIONS_TABLE_NAME = var.ipv_sessions_table_name
      CREDENTIAL_ISSUER_CONFIG_PARAMETER_STORE_KEY = var.credential_issuer_config_parameter_store_key
    }
  }

  # There is an outstanding bug in terraform (Issue #3630) that means it always tries to update the
  # last modified date, even if no other attributes in the lambda need changing
  lifecycle {
    ignore_changes = [last_modified, filename]
  }
}

resource "aws_lambda_alias" "alias_active" {
  name             = "active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.lambda_function.arn
  function_version = aws_lambda_function.lambda_function.version
}


resource "aws_api_gateway_resource" "endpoint" {
  rest_api_id = var.rest_api_id
  parent_id   = var.root_resource_id
  path_part   = var.path_part
}

resource "aws_api_gateway_method" "endpoint_method" {
  rest_api_id      = var.rest_api_id
  resource_id      = aws_api_gateway_resource.endpoint.id
  http_method      = var.http_method
  authorization    = "NONE"
  api_key_required = false
}

resource "aws_api_gateway_integration" "endpoint_integration" {
  rest_api_id = var.rest_api_id
  resource_id = aws_api_gateway_resource.endpoint.id
  http_method = aws_api_gateway_method.endpoint_method.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_alias.alias_active.invoke_arn
}

resource "aws_lambda_permission" "endpoint_execution_base_permission" {
  statement_id  = "AllowAPIGatewayInvokeBase"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${var.rest_api_execution_arn}/*/${aws_api_gateway_method.endpoint_method.http_method}/${var.path_part}"
}

resource "aws_lambda_permission" "endpoint_execution_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function.function_name
  principal     = "apigateway.amazonaws.com"
  qualifier     = aws_lambda_alias.alias_active.name
  source_arn    = "${var.rest_api_execution_arn}/*/${aws_api_gateway_method.endpoint_method.http_method}/${var.path_part}"
}
