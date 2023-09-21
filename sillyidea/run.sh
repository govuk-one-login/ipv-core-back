#!/usr/bin/env bash

if [[ -z "${ENVIRONMENT}" ]]; then
  echo "ENVIRONMENT not set. Go set it."
  exit 1
fi

export CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN=arn:aws:lambda:eu-west-2:388905755587:function:getContraIndicatorCredential-production
export CI_STORAGE_GET_LAMBDA_ARN=arn:aws:lambda:eu-west-2:388905755587:function:getContraIndicators-production
export CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN=arn:aws:lambda:eu-west-2:388905755587:function:postMitigations-production
export CI_STORAGE_PUT_LAMBDA_ARN=arn:aws:lambda:eu-west-2:388905755587:function:putContraIndicators-production
export CLIENT_AUTH_JWT_IDS_TABLE_NAME="client-auth-jwt-ids-$ENVIRONMENT"
export CLIENT_OAUTH_SESSIONS_TABLE_NAME="client-oauth-sessions-v2-$ENVIRONMENT"
export CONFIG_SERVICE_CACHE_DURATION_MINUTES=0
export CRI_OAUTH_SESSIONS_TABLE_NAME="cri-oauth-sessions-$ENVIRONMENT"
export CRI_RESPONSE_TABLE_NAME="cri-response-$ENVIRONMENT"
export IPV_SESSIONS_TABLE_NAME="sessions-$ENVIRONMENT"
export IS_LOCAL=false
export SIGNING_KEY_ID_PARAM=/dev-chrisw/core/self/signingKeyId
export SQS_AUDIT_EVENT_QUEUE_URL=https://sqs.eu-west-2.amazonaws.com/130355686670/audit-sqs-AuditEventQueue-JnUaGH1DLHLZ
export USER_ISSUED_CREDENTIALS_TABLE_NAME=user-issued-credentials-v2-"$ENVIRONMENT"
export LAMBDA_TASK_ROOT=handler

./gradlew :sillyidea:run --no-daemon
