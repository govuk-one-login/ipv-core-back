# RevokeVcsHandler

What this lambda is for and does: https://govukverify.atlassian.net/browse/PYIC-4555

To run this lambda, create an appropriate payload including userIds with vcs in the the appropriate environment.

```bash
aws-vault exec <profile> -- aws lambda invoke --function-name revoke-vcs-<env> --invocation-type RequestResponse --payload fileb://revokeVcsLambdaPayload.json
```

This lambda iterates the `userId` and `criId` pairs and for each:
1. Archives the vc, entering it into the `revoked-user-credentials-{env}` table
2. Sends `IPV_VC_REVOKED` audit event
3. Deletes the vc in the `user-issued-credentials-v2-{env}` table
