#!/bin/bash

sam build &&
sam validate --lint &&
sam deploy --template-file ./.aws-sam/build/template.yaml \
--resolve-s3 \
--stack-name account-delete \
--region eu-west-2 \
--parameter-overrides \
ParameterKey=Environment,ParameterValue=build \
ParameterKey=PermissionsBoundary,ParameterValue=arn:aws:iam::457601271792:policy/account-delete-pipeline-AppPermissionsBoundary-060f92265d2a \
ParameterKey=CodeSigningConfigArn,ParameterValue=arn:aws:lambda:eu-west-2:457601271792:code-signing-config:csc-093d8d005655fbb01 \
ParameterKey=VpcStackName,ParameterValue=vpc \
--capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
--signing-profiles DeleteUserDataFunction=SigningProfile_QNJgizjq9q4G \
--tags Product="GOV.UK Sign In" \
         System="IPV Core" \
         Environment="build"
