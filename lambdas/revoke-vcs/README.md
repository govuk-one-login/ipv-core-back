# RevokeVcsHandler

What this lambda is for and does: https://govukverify.atlassian.net/browse/PYIC-4555

To run this lambda, create an appropriate payload including userIds with vcs in the the appropriate environment.

```bash
aws-vault exec <profile> -- aws lambda invoke --function-name revoke-vcs-<env> --invocation-type RequestResponse --payload fileb://revokeVcsLambdaPayload.json response.json
```

This lambda iterates the `userId` and `criId` pairs and for each:
1. Archives the vc, entering it into the `revoked-user-credentials-{env}` table
2. Sends `IPV_VC_REVOKED` audit event
3. Deletes the vc in the `user-issued-credentials-v2-{env}` table

For each VC we try to delete we will do the following:
```mermaid
flowchart LR
%% VC does exist and can send audit event
0[Start] --> A[Assert VC exists]
A --success--> B[Archive VC]
B --success--> C[Send audit event:\n IPV_VC_REVOKED]
C --success--> D[Delete VC]
D --success--> E([Successfully archived & revoked\n audit event: IPV_VC_REVOKED])
E ----> -1[Next VC]

%% VC does exist but can't send audit event
C --failure--> F([Unsuccessfully archived & revoked])
F --> BREAK[Break]

%% VC doesn't exist and can't send audit event
G --failure--> F
    
%% VC doesn't exist but can send audit event
A --failure--> G[Send audit event:\n IPV_VC_REVOKED_FAILURE]
G --success--> H([Unsuccessfully archived & revoked\n audit event: IPV_VC_REVOKED_FAILURE])
H --> -1

%% Failure archiving
B --failure--> G

%% Failure deleting VC
D --failure--> I[Send audit event:\n IPV_VC_REVOKED_FAILURE]
I --success--> J([Successfully archived & unsuccessfully revoked\n audit events: IPV_VC_REVOKED\n & IPV_VC_REVOKED_FAILURE])
J ---> -1

%% Failure sending IPV_VC_REVOKED_FAILURE for VC deletion failure
I --failure--> K([Successfully archived & unsuccessfully revoked\n audit event: IPV_VC_REVOKED])
K --> BREAK
```

Either the process works or we get one of the two following failure paths:
1. `IPV_VC_REVOKED_FAILURE` audit event
2. The loop is broken and logs indicate why and where

Either way, we can identify what error caused each failure path in the logs, and the progress through the list at which it occurred.
