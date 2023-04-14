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
Requests evidence from a credential issuer

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



## Pre-Commit Checking / Verification

Completely optional, there is a `.pre-commit-config.yaml` configuration setup in this repo, this uses [pre-commit](https://pre-commit.com/) to verify your commit before actually commiting, it runs the following checks:

* Check Json files for formatting issues
* Fixes end of file issues (it will auto correct if it spots an issue - you will need to run the git commit again after it has fixed the issue)
* It automatically removes trailing whitespaces (again will need to run commit again after it detects and fixes the issue)
* Detects aws credentials or private keys accidentally added to the repo
* runs cloud formation linter and detects issues
* runs checkov and checks for any issues.


### Dependency Installation
To use this locally you will first need to install the dependencies, this can be done in 2 ways:

#### Method 1 - Python pip

Run the following in a terminal:

```
sudo -H pip3 install checkov pre-commit cfn-lint
```

this should work across platforms

#### Method 2 - Brew

If you have brew installed please run the following:

```
brew install pre-commit ;\
brew install cfn-lint ;\
brew install checkov
```

### Post Installation Configuration
once installed run:
```
pre-commit install
```

To update the various versions of the pre-commit plugins, this can be done by running:

```
pre-commit autoupdate && pre-commit install
```

This will install / configure the pre-commit git hooks,  if it detects an issue while committing it will produce an output like the following:

```
 git commit -a
check json...........................................(no files to check)Skipped
fix end of files.........................................................Passed
trim trailing whitespace.................................................Passed
detect aws credentials...................................................Passed
detect private key.......................................................Passed
AWS CloudFormation Linter................................................Failed
- hook id: cfn-python-lint
- exit code: 4
W3011 Both UpdateReplacePolicy and DeletionPolicy are needed to protect Resources/PublicHostedZone from deletion
core/deploy/dns-zones/template.yaml:20:3
Checkov..............................................(no files to check)Skipped
- hook id: checkov
```

# SAM (Serverless Application Model)

## Build
```
sam build --cached --parallel
```

As part of the build stage tests are disabled. To enable them run the following:
```
# Build with Unit Tests and Integration Tests
GRADLE_SAM_EXECUTE_TEST=1 sam build -cached --parallel
```

## Deploy
```
sam deploy --debug --config-file ./samconfig.toml --config-env dev-{{environment}}
```

## Sync
```
sam sync --watch --config-file samconfig.toml --config-env {{environment}} --stack-name core-back-dev-{{environment}} --region eu-west-2
```
