# networking module

This directory contains a terraform module which creates the low-level networking infrastructure required to deploy the components in this repo.
In particular, it creates:

- VPC
- subnets, routing tables, internet gateway

It may in future also contain some other useful shared network-related things, such as security groups for cross-component communication, or route 53 zones, or service discovery things.

The intended usage is that this module creates resources, which are then discovered via terraform data sources in other modules.

## Variables

|Name|Type|Description|
|:---|:---|:---|
|`environment`|string|Name of environment to deploy. Used to tag resources.|
