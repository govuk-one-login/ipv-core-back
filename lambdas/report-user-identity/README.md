# ReportUserIdentityHandler

---

## Terms

- `PROFILE` is the aws account profile you want to use for this call. E.g. if you were running it in `build` then it could be `core-build-admin`.
- `ENVIRONMENT` is the environment to run it in, linked to `PROFILE` because in the same example it would have to be `build`.

---

## Description

- This lambda scans the dynamoDb table "user-issued-credentials-v2-${Environment}" to generate user's identity type and its constitute.

- This lambda works on user credentials in the `user-issued-credentials-v2-ENVIRONMENT` table ([e.g.](https://eu-west-2.console.aws.amazon.com/dynamodbv2/home?region=eu-west-2#item-explorer?table=user-issued-credentials-v2-build)).

---

## Running the lambda

> This lambda should not be invoked in production without explicit sign-off from stakeholders

### Command

```bash
aws-vault exec PROFILE -- \
  aws lambda invoke \
    --function-name report-user-identity-ENVIRONMENT \
    --invocation-type RequestResponse \
    --cli-read-timeout 600
```

NB: the read timeout is increased over the default to receive output file from lambda even after a long execution period.

### Request payload
Step-1 If only want to gather unique users from tactical storage (with no lastEvaluatedKey).
```json
{
  "continueUniqueUserScan": true,
  "continueUserIdentityScan": false
}
```
AWS lambda has got max timeout value of 900 seconds (15 minutes). And as in live we got around 2.5M VCs we'll need
to run this number of times with lastEvaluatedKey from previous run scan to gather unique users.

If only want to gather unique users from tactical storage (with lastEvaluatedKey from last run output result).
```json
{
  "continueUniqueUserScan": true,
  "tacticalStoreLastEvaluatedKey": {
    "userId": {
        "S": "4w8niZpiMy6qz1mntFA5u"
    },
   "credentialIssuer": {
        "S": "4w8niZpiMy6qz1mntFA5u"
    }
  },
  "continueUserIdentityScan": true
}
```
Step-2 If all unique users are gathered from tactical storage (there will be no tacticalStoreLastEvaluatedKey value in last run output result).
```json
{
  "continueUniqueUserScan": false,
  "continueUserIdentityScan": true
}
```
As again to gather identity details for those unique users (in million), we need to run this number of times with lastEvaluatedKey
from previous run scan for already gathered unique users. Run it n number of times till there be userIdentitylastEvaluatedKey
value in last run output.
```json
{
  "continueUniqueUserScan": false,
  "continueUserIdentityScan": true,
  "userIdentitylastEvaluatedKey": {
    "hashUserId": {
      "S": "4w8niZpiMy6qz1mntFA5u"
    }
  }
}
```
Step-3 If all unique users are gathered from tactical storage (there will be no tacticalStoreLastEvaluatedKey value in last run output result).
Also identity details are gathered for all unique users (there will be no userIdentitylastEvaluatedKey value in last run output result)

Then we just need to generate report summary output.
```json
{
  "continueUniqueUserScan": false,
  "continueUserIdentityScan": false
}
```

### Output

- Logging statuses with progress level throughout the report processing.

```json
{
  "summary": {
    "Total P2": 12,
    "Total P2 migrated": 2,
    "Total P1": 1,
    "Total P0": 1,
    "constituentVcsTotal": {
      "address,fraud,kbv,ukPassport": 1,
      "address,dcmaw-passport,fraud": 3,
      "address,claimedIdentity,f2f-passport,fraud": 1
    }
  },
  "tacticalStoreLastEvaluatedKey": {
    "userId": {
      "S": "4w8niZpiMy6qz1mntFA5u"
    },
    "credentialIssuer": {
      "S": "4w8niZpiMy6qz1mntFA5u"
    }
  },
  "userIdentitylastEvaluatedKey": {
    "hashUserId": {
      "S": "4w8niZpiMy6qz1mntFA5u"
    }
  },
  "buildReportLastEvaluatedKey": {
    "hashUserId": {
      "S": "4w8niZpiMy6qz1mntFA5u"
    }
  }
}
```
Output result when both process to gather unique users from tactical storage and then to find identity
details for those gathered users completed.
```json
{
  "summary": {
    "Total P2": 12,
    "Total P2 migrated": 2,
    "Total P1": 1,
    "Total P0": 1,
    "constituentVcsTotal": {
      "address,fraud,kbv,ukPassport": 1,
      "address,dcmaw-passport,fraud": 3,
      "address,claimedIdentity,f2f-passport,fraud": 1
    }
  }
}
```
