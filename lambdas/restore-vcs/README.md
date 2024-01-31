# RestoreVcsHandler

What this lambda is for and does: https://govukverify.atlassian.net/browse/PYIC-4602

To run this lambda, create an appropriate payload including userIds with vcs to be restored in the appropriate environment.

```bash
aws-vault exec <profile> -- aws lambda invoke --function-name restore-vcs-<env> --invocation-type RequestResponse --payload fileb://restoreVcsLambdaPayload.json response.json
```

This lambda iterates the `userId` and `criId` pairs and for each:
1. Restores the vc, entering it into the `user-issued-credentials-{env}` table
2. Sends `IPV_VC_RESTORED` audit event
3. Deletes the vc in the `user-credentials-v2-{env}` table
