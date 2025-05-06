#!/bin/bash

set -eo pipefail

get_current_status() {
  aws codepipeline get-pipeline-state --name "$1" \
    | jq -r '.stageStates[] | select(.stageName == "Deploy") | .actionStates[] | select(.actionName == "Deploy") | .latestExecution.status'
}

generate_traffic() {
  while true; do
    echo "Running @TrafficGeneration tests"
    npm run test:"$TEST_ENV" -- --profile trafficGeneration --tags '@TrafficGeneration' || true
  done
}

# Ensure the test report dir exists
[ -e "$TEST_REPORT_ABSOLUTE_DIR" ] && mkdir -p "$TEST_REPORT_ABSOLUTE_DIR"

ENVIRONMENT_SECRET=$(aws secretsmanager get-secret-value --secret-id ApiTestEnvironment | jq -r .SecretString)
if echo "$ENVIRONMENT_SECRET" | grep -qi "devShared"; then
  TEST_ENV="devShared"
else
  TEST_ENV="build"
fi

CORE_BACK_INTERNAL_API_KEY=$(aws secretsmanager get-secret-value --secret-id CoreBackInternalTestingApiKey | jq -r .SecretString)
export CORE_BACK_INTERNAL_API_KEY

EVCS_STUB_API_KEY=$(aws secretsmanager get-secret-value --secret-id /build/core/evcs/apiKey | jq -r .SecretString)
export EVCS_STUB_API_KEY

CRI_STUB_GEN_CRED_API_KEY=$(aws secretsmanager get-secret-value --secret-id CriStubGenCredApiKey | jq -r .SecretString)
export CRI_STUB_GEN_CRED_API_KEY

MANAGEMENT_TICF_API_KEY=$(aws secretsmanager get-secret-value --secret-id /build/core/credentialIssuers/ticf/connections/stub/apiKey | jq -r .SecretString)
export MANAGEMENT_TICF_API_KEY

MANAGEMENT_CIMIT_STUB_API_KEY=$(aws secretsmanager get-secret-value --secret-id /build/core/cimitManagementApi/apiKey | jq -r .SecretString)
export MANAGEMENT_CIMIT_STUB_API_KEY

CIMIT_INTERNAL_API_KEY=$(aws secretsmanager get-secret-value --secret-id /build/core/cimitApi/apiKey | jq -r .SecretString)
export CIMIT_INTERNAL_API_KEY

cd /api-tests

if [[ "${DEV_PLATFORM_STAGE}" == "TRAFFIC_TEST" ]]; then
  sleep 30 # Wait to ensure deploy action is up and running
  generate_traffic & # Start API tests to generate traffic and send to the background
  tests_pid=$!
  trap 'kill $tests_pid' EXIT
  echo "Started running API tests in background with PID: ${tests_pid}"

  core_back_pipeline_name=$(aws codepipeline list-pipelines \
    | jq -r '.pipelines[] | select(.name | contains("core-back-pipeline")) | .name')
  deploy_status=$(get_current_status "${core_back_pipeline_name}")

  start_time=$(date +%s)
  echo "Start time: ${start_time}"
  # Loop until the deploy action is not in progress, or until 30 minutes has passed
  while [[ "${deploy_status}" = "InProgress" && "${start_time}" -gt $(($(date +%s)-1800)) ]]; do
    sleep 10
    deploy_status=$(get_current_status "${core_back_pipeline_name}")
  done

  echo -e "\n\nDeploy status: '${deploy_status}' - Stopping tests execution"
  exit 0

else
  echo "Running API tests against the $TEST_ENV environment"
  npm run test:"$TEST_ENV" -- --profile codepipeline

  api_tests_exit_code=$?
  cp reports/api-tests-cucumber-report.json "$TEST_REPORT_ABSOLUTE_DIR"

  if [ $api_tests_exit_code != 0 ]; then
    echo "API tests failed with exit code ${api_tests_exit_code}"
    exit $api_tests_exit_code
  else
    echo "API tests passed"
  fi
fi
