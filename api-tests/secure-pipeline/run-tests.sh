#!/bin/bash

set -eo pipefail

# Ensure the test report dir exists
[ -e "$TEST_REPORT_ABSOLUTE_DIR" ] && mkdir -p "$TEST_REPORT_ABSOLUTE_DIR"

echo "Running API tests against the build environment"

CORE_BACK_INTERNAL_API_KEY=$(aws secretsmanager get-secret-value --secret-id CoreBackInternalTestingApiKey | jq -r .SecretString)
export CORE_BACK_INTERNAL_API_KEY

EVCS_STUB_API_KEY=$(aws secretsmanager get-secret-value --secret-id /build/core/evcs/apiKey | jq -r .SecretString)
export EVCS_STUB_API_KEY

CRI_STUB_GEN_CRED_API_KEY=$(aws secretsmanager get-secret-value --secret-id CriStubGenCredApiKey | jq -r .SecretString)
export CRI_STUB_GEN_CRED_API_KEY

MANAGEMENT_TICF_API_KEY=$(aws secretsmanager get-secret-value --secret-id /build/core/credentialIssuers/ticf/connections/stub/apiKey | jq -r .SecretString)
export MANAGEMENT_TICF_API_KEY

MANAGEMENT_CIMIT_STUB_API_KEY=$(aws ssm get-parameter --name /tests/core-back-build/cimit_api_key | jq -r .Parameter.Value)
export MANAGEMENT_CIMIT_STUB_API_KEY

CIMIT_INTERNAL_API_KEY=$(aws secretsmanager get-secret-value --secret-id /build/core/cimitApi/apiKey | jq -r .SecretString)
export CIMIT_INTERNAL_API_KEY

cd /api-tests

npm run test:build -- --profile codepipeline

api_tests_exit_code=$?
cp reports/api-tests-cucumber-report.json "$TEST_REPORT_ABSOLUTE_DIR"

if [ $api_tests_exit_code != 0 ]
then
  echo "API tests failed with exit code ${api_tests_exit_code}"
  exit $api_tests_exit_code
else
  echo "API tests passed"
fi
