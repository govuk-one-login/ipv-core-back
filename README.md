# Digital Identity IPV Core Back

This the back-end code for the core of the Identity Proofing and Verification (IPV) system within the GDS digital identity platform, GOV.UK One Login.

The following projects are related to the di-ipv-core-back, providing additional functionality:
* [di-ipv-core-front](https://github.com/govuk-one-login/ipv-core-front) - Front end code for the core of the Identity Proofing and Verification (IPV) system.
* [di-ipv-core-tests](https://github.com/govuk-one-login/ipv-core-tests) - Feature tests for the core of the Identity Proofing and Verification (IPV) system.
* [di-ipv-core-common-infra](https://github.com/govuk-one-login/ipv-core-common-infra) - Infrastructure and configuration values for the core of the Identity Proofing and Verification (IPV) system.
* [di-ipv-stubs](https://github.com/govuk-one-login/ipv-stubs) - Stubs for IPV Core dependencies (i.e. CRIs), used for testing in dev/build and occasionally higher environments.

## Development
The di-ipv-core-back is a mix of Java and Node.js AWS Lambdas. The following section should give you a guide how to get started developing functionality for di-ipv-core-back.

### Dependencies
We mainly use Mac and Linux environments when developing di-ipv-core-back. Most of the tools can be installed through [Homebrew](https://brew.sh/) using the following:
```bash
brew install --cask intellij-idea
brew install --cask docker
brew install jq
brew install alphagov/gds/gds-cli
brew tap aws/tap
brew install awscli
brew install aws-sam-cli
```

We use [pre-commit](https://pre-commit.com/) to help with linting. This configured through the [.pre-commit-config.yaml](pre-commit-config.yaml) configuration setup in this repo, this uses pre-commit to verify your commit before actually commiting, it runs the following checks:
* Check Json files for formatting issues
* Fixes end of file issues (it will auto correct if it spots an issue - you will need to run the git commit again after it has fixed the issue)
* It automatically removes trailing whitespaces (again will need to run commit again after it detects and fixes the issue)
* Detects aws credentials or private keys accidentally added to the repo
* Runs Cloud Formation linter and detects issues
* Runs checkov and checks for any issues.

You can install pre-commit using Homebrew:
```bash
brew install pre-commit ;\
brew install cfn-lint ;\
brew install checkov
```

or via Python

```bash
sudo -H pip3 install checkov pre-commit cfn-lint
```

And initialising pre-commit by running the following:
```bash
pre-commit install
```

To update the various versions of the pre-commit plugins, this can be done by running:
```bash
pre-commit autoupdate && pre-commit install
```

### Building
See the [Deployment Documentation](deploy/README.md) for information on building the di-ipv-core-back project.

### Deployment
See the [Deployment Documentation](deploy/README.md) for information on deploying the di-ipv-core-back project.

### Testing
The di-ipv-core-back has a number of different tests:
* Unit Tests - Each lambda contains unit tests which test a classes functionality in isolation. These tests can be found within the `lambda\*\src\test` folder.
* Integration Tests - Integration tests are found in the `integration-test` folder and test the functionality of `di-ipv-core-back` running on an AWS test environment.
* Feature Tests - Cucumber feature tests for the core of the Identity Proofing and Verification (IPV) system reside in the [di-ipv-core-tests](https://github.com/govuk-one-login/ipv-core-tests) project. The tests run against a deployment of di-ipv-core-back and di-ipv-core-front and test the IPV Core user journeys.

## Code structure
The application is configured as a Gradle project with a sub-project for each Lambda. The following are the main folders and their use:
| Folder | Description |
| ------ | ----------- |
| deploy | Contains the AWS Resources such as Cloud Formation Templates and Step Function Definitions required to build and deploy the di-ipv-core-back component.
| integration-test | Contains the Integration Tests used to test various components of di-ipv-core running on AWS. |
| lambdas | Source code to the Java and Node.js AWS Lambdas which come together to form di-ipv-core-back |
| lib & libs | Shared sources used by each of the Lambdas |
| openAPI | Open API Definition used by the Internal and External API Gateway |

## Environment variables

* IS_LOCAL - This only needs to be assigned when running locally. This is set to `true` in `local-startup`.
* BEARER_TOKEN_TTL - The bearer token time to live in seconds. If not set this defaulted to a value in `ConfigurationService`

### DynamoDB table name variables:
Each environment has a specific table name prefix e.g. `dev-{dynamo-table-name}`

These values are automatically assigned by terraform within the `aws_lambda_function` resource
* ACCESS_TOKENS_TABLE_NAME
* AUTH_CODES_TABLE_NAME
* USER_ISSUED_CREDENTIALS_TABLE_NAME
* CRI_RESPONSE_TABLE_NAME

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
