resource "aws_api_gateway_rest_api" "ipv_internal" {
  name        = "${var.environment}-ipv-internal"
  description = "The api accessed by internal IPV systems, e.g. di-ipv-core-front"
  tags        = local.default_tags
}

resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = aws_api_gateway_rest_api.ipv_internal.id

  triggers = {
    authorize = module.authorize.trigger
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