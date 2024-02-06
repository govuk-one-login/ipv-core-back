# RevokeVcsHandler

---

## Terms

- `PROFILE` is the aws account profile you want to use for this call. E.g. if you were running it in `build` then it could be `core-build-admin`.
- `ENVIRONMENT` is the environment to run it in, linked to `PROFILE` because in the same example it would have to be `build`.
- `PAYLOAD_PATH` is the path (from the working directory) to the JSON file with the payload in it.
- `OUTPUT_FILE` is the path (from the working directory) which gets written to with the lambda output.

---

## Description

- This lambda takes a payload with an array of key pairs to iterate through and revoke the associated verifiable credential (VC) for each.
- In order to safely revoke these VCs we perform the following operation on each VC:
  1. Read the VC from the main table, fails if not exists.
     - The `userId` and `criId` keys provided in each entry of the payload list uniquely identify a VC.
  2. Enter VC into the archive table.
  3. Submit audit event `IPV_VC_REVOKED` for the revocation.
  4. Delete the VC from the main table.
  5. Log the progress through the list.


- This lambda works on user credentials in the `user-issued-credentials-v2-ENVIRONMENT` table ([e.g.](https://eu-west-2.console.aws.amazon.com/dynamodbv2/home?region=eu-west-2#item-explorer?table=user-issued-credentials-v2-build)).
- The lambda archives during revocation in the `revoked-user-credentials-ENVIRONMENT` table ([e.g.](https://eu-west-2.console.aws.amazon.com/dynamodbv2/home?region=eu-west-2#item-explorer?table=revoked-user-credentials-build)).
- In the case of failures which can have audit events, we send the audit event `IPV_VC_REVOKED_FAILURE`.
- In the case where we cannot send audit events, we break the loop through the list.

---

## Running the lambda

> This lambda should not be run by anyone without the explicit sign-off of stakeholders.

### Payload

- To revoke Vcs, this lambda needs a payload file with a list of `userId`'s paired with `criId`'s. 
- These must be associated with VCs in the `user-issued-credentials-v2-ENVIRONMENT` table.
- e.g. payload at `PAYLOAD_PATH`:
```json
{
  "userIdCriIdPairs": [
    { "userId": "urn:uuid:878e1871-8b7d-4a17-91ba-516bd86a0abc", "criId": "passport" },
    { "userId": "urn:uuid:96aecbd3-7cce-47a3-80b4-b4211412ebb1", "criId": "drivingLicense" },
    { "userId": "urn:uuid:0243cd17-f9b3-4617-9441-040b1860664e", "criId": "kbv" }
  ]
}
```

### Command

```bash
aws-vault exec PROFILE -- \
  aws lambda invoke \
    --function-name revoke-vcs-ENVIRONMENT \
    --invocation-type RequestResponse \
    --payload fileb://PAYLOAD_PATH \
    OUTPUT_PATH \
    --cli-read-timeout 600
```

NB: the read timeout is increased over the default to receive output file from lambda even after a long execution period.

### Output

- Logging statuses with progress level through the list.
- Audit events: `IPV_VC_REVOKED` & `IPV_VC_REVOKED_FAILURE`, which have the userId associated.
  - `IPV_VC_REVOKED` additionally contains issuer & evidence stored.
  - `IPV_VC_REVOKED_FAILURE` additionally contains `criId` in the extension.
- The lambda also outputs to `OUTPUT_FILE` which contains the summary view of the run.
  - e.g. summary at `OUTPUT_FILE`:

```json
{
  "successes" : [
    { "userIdCriIdPair": { "userId": "urn:uuid:878e1871-8b7d-4a17-91ba-516bd86a0abc", "criId": "passport" } },
    { "userIdCriIdPair": { "userId": "urn:uuid:0243cd17-f9b3-4617-9441-040b1860664e", "criId": "kbv" } }
  ],
  "failures": [
    { 
      "userIdCriIdPair": { "userId": "urn:uuid:96aecbd3-7cce-47a3-80b4-b4211412ebb1", "criId": "drivingLicense" },
      "errorMessage": "VC cannot be found"
    }
  ]
}
```

### Error handling

For each VC we will do the following:

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
