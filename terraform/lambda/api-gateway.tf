resource "aws_api_gateway_rest_api" "ipv_internal" {
  name = "${var.environment}-ipv-internal"

  tags = local.default_tags
}
