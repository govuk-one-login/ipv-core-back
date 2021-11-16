# lambda module

This directory contains a terraform module which creates ... components in this repo.
In particular, it creates:

- an API gateway resource
- lambdas ready to have code deployed to them.

Note that this module does not deploy actual code.
Code deploys are done separately via concourse calling `aws lambda update-function-code`.
