#!/bin/bash

set -eo pipefail

# Ensure the test report dir exists
[ -e "$TEST_REPORT_ABSOLUTE_DIR" ] && mkdir -p "$TEST_REPORT_ABSOLUTE_DIR"

echo "Running API tests against the build environment"

CORE_BACK_INTERNAL_API_KEY=$(aws secretsmanager get-secret-value --secret-id CoreBackInternalTestingApiKey | jq -r .SecretString)
export CORE_BACK_INTERNAL_API_KEY

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
