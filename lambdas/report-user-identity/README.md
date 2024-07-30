# ReportUserIdentityHandler

---

## Terms

- `PROFILE` is the aws account profile you want to use for this call. E.g. if you were running it in `build` then it could be `core-build-admin`.
- `ENVIRONMENT` is the environment to run it in, linked to `PROFILE` because in the same example it would have to be `build`.
- `OUTPUT_FILE` is the path (from the working directory) which gets written to with the lambda output.

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
    OUTPUT_PATH \
    --cli-read-timeout 600
```

NB: the read timeout is increased over the default to receive output file from lambda even after a long execution period.

### Output

- Logging statuses with progress level through the scan.
- The lambda also outputs to `OUTPUT_FILE` which contains the summary view of the run.
  - e.g. summary at `OUTPUT_FILE`:

```json
{
  "summary": {
    "Total P2": 1,
    "Total P1": 1,
    "Total P0": 1
  },
  "users": [
    {
      "userId": "urn:uuid:878e1871-8b7d-4a17-91ba-516bd86a0abc",
      "identity": "P2",
      "constituteCriDocumentType": "drivingLicence, address, fraud, kbv"
    },
    {
      "userId": "urn:uuid:0243cd17-f9b3-4617-9441-040b1860664e",
      "identity": "P1",
      "constituteCriDocumentType": "address, fraud, kbv"
    },
    {
      "userId": "urn:uuid:0243cb18-f9b3-4617-9441-040b1860688e",
      "identity": "P0",
      "constituteCriDocumentType": "address, fraud, kbv"
    }
  ]
}
```

### Error handling
