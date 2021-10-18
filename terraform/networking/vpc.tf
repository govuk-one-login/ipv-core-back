resource "aws_vpc" "ipv" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.default_tags, {
    Name = "${var.environment}-ipv-vpc"
  })
}

data "aws_availability_zones" "available" {}

resource "aws_subnet" "ipv_public" {
  count             = length(data.aws_availability_zones.available.names)
  vpc_id            = aws_vpc.ipv.id
  cidr_block        = "10.1.${count.index + 128}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.default_tags, {
    Name = "${var.environment}-public-${data.aws_availability_zones.available.names[count.index]}"
  })
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.ipv.id

  tags = merge(local.default_tags, {
    Name = "${var.environment}-ipv"
  })
}

resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.ipv.id

  tags = merge(local.default_tags, {
    Name = "${var.environment}-public-ipv"
  })
}

resource "aws_route" "public_to_internet" {
  route_table_id         = aws_route_table.public_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public_to_internet" {
  count = length(data.aws_availability_zones.available.names)

  route_table_id = aws_route_table.public_route_table.id
  subnet_id      = aws_subnet.ipv_public[count.index].id
}
