resource "aws_api_gateway_rest_api" "ipv_internal" {
  name = "${var.environment}-ipv-internal"

  tags = local.default_tags
}


resource "aws_lambda_function" "authorize" {
  filename         = var.lambda_zip_file
  function_name    = "${var.environment}-authorize"
  role             = aws_iam_role.lambda_iam_role.arn
  handler          = "uk.gov.di.ipv.lambda.AuthorizationHandler::handleRequest"
  runtime          = "java11"
  source_code_hash = filebase64sha256(var.lambda_zip_file)
  publish          = true
  timeout          = 30
  memory_size      = 2048
}

resource "aws_lambda_alias" "authorize_active" {
  name             = "${var.environment}-active"
  description      = "Alias pointing at active version of Lambda"
  function_name    = aws_lambda_function.authorize.arn
  function_version = aws_lambda_function.authorize.version
}
