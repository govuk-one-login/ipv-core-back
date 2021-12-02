# Digital Identity IPV Core Back

This the back-end code for the core of the Identity Proofing and Verification (IPV) system within the GDS digital identity platform, GOV.UK Sign In.

## Environment variables

* IS_LOCAL - This only needs to be assigned when running locally. This is set to `true` in `local-startup`.
* BEARER_TOKEN_TTL - The bearer token time to live in seconds. If not set this defaulted to a value in `ConfigurationService`
### DynamoDB table name variables:
Each environment has a specific table name prefix e.g. `dev-{dynamo-table-name}`

These values are automatically assigned by terraform within the `aws_lambda_function` resource
* ACCESS_TOKENS_TABLE_NAME
* AUTH_CODES_TABLE_NAME
* USER_ISSUED_CREDENTIALS_TABLE_NAME


## REST API interface

### Request Evidence
<hr/>
Request evidence from a credential issuer

* **URL**

  `/request-evidence`

* **Method:**

  `POST`

* **Content-Type:**

    `application/x-www-form-urlencoded`

* **URL Params**

   None

* **Data Params**
 
  * `authorization_code [string, required]`
  * `credential_issuer_id [string, required]`
  * `session_id [string, required]`


* **Success Response:**

  * Code: `200`
  * Content: `{}`

* **Error Response:**

  * Code: `400` 
  * Content: `{ "code" : "1001", "message": "error message" }`
