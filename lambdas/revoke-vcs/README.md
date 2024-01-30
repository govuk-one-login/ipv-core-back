# RevokeVcsHandler

What this lambda is for and does: https://govukverify.atlassian.net/browse/PYIC-4555

To run this lambda, create an appropriate payload including userIds with vcs in the the appropriate environment.

```bash
aws-vault exec <profile> -- aws lambda invoke --function-name revoke-user-credentials-<env> --invocation-type RequestResponse --payload fileb://revokeVcsLambdaPayload.json response.json
```

This lambda iterates over batches of 100 userIds and for each:
1. Archives the vc entering it into the revoked-user-credentials-Vloo-{env} table
2. Sends an audit event
3. Deletes the vc in the user-credentials-v2-{env} table
