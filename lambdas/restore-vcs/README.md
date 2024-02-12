# RestoreVcsHandler

---

## Description

This lambda mirrors the functionality of [RevokeVcsHandler](lambdas/revoke-vcs/README.md), except for some differences:
1. The direction of change of VC ownership is opposite
2. The lambda does not send a failing audit event

---

## Running the lambda

> This lambda should not be invoked in production without explicit sign-off from stakeholders

### Payload

- The payload is the same as for the revoke lambda.

### Command

```bash
aws-vault exec PROFILE -- \
  aws lambda invoke \
    --function-name restore-vcs-ENVIRONMENT \
    --invocation-type RequestResponse \
    --payload fileb://PAYLOAD_PATH \
    OUTPUT_PATH \
    --cli-read-timeout 600
```

NB: the only difference is the function name

### Output

- Logging is the same as in the revoke lambda.
- Audit events: `IPV_VC_RESTORED` which has the userId associated.
  - There is no audit event associated to failure.
- The lambda does not output a file with a summary like the revoke lambda
