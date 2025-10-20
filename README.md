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

### Secrets
To set up secrets, copy the `secrets.gradle.template` to `secrets.gradle` and enter values for each variable.

The DI data-vocab classes are published to a GitHub maven repository (https://github.com/govuk-one-login/data-vocab/packages)
and you require a personal access token to download these.

See [Managing your personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
for instructions on creating a token. The token must have the `read:packages` permission.

### Building
See the [Deployment Documentation](deploy/README.md) for information on building the di-ipv-core-back project.

### Deployment
See the [Deployment Documentation](deploy/README.md) for information on deploying the di-ipv-core-back project.

### Development environments
Instantiating core-back to run in a safe environment can be done using:
- [local-running](local-running/README.md), which exposes core-back on localhost
- [dev-deploy tool](https://github.com/govuk-one-login/ipv-core-common-infra/blob/main/utils/dev-deploy/README.md), which deploys to a user/ perf environment
- [dev-pipeline](https://github.com/govuk-one-login/ipv-core-back/actions/workflows/secure-post-merge.yml), which deploys to the [shared dev environment](https://orch.stubs.account.gov.uk/?defaultEnvironment=DEV)

### Testing
The di-ipv-core-back has a number of different tests:
* Unit Tests - Each lambda contains unit tests which test a classes functionality in isolation. These tests can be found within the `lambda\*\src\test` folder.
* [API Tests](api-tests/README.md) - Test core functionality and user routing without having to use the frontend.
* Feature Tests - Cucumber feature tests for the core of the Identity Proofing and Verification (IPV) system reside in the [di-ipv-core-tests](https://github.com/govuk-one-login/ipv-core-tests) project. The tests run against a deployment of di-ipv-core-back and di-ipv-core-front and test the IPV Core user journeys.
* Pact tests - Contract tests that ensure that we're providing and consuming the correct JSON in our integrations with other services

#### Running API tests locally
di-ipv-core-back can be run [locally](local-running/README.md), allowing [API Tests](api-tests/README.md) to be run against it:
```
cd api-tests
npm run test:local
```

#### Running provider pact tests locally
To run provider pact tests locally you will need to have a local copy of the pact file. You will need an account with the pact broker - ask in the #introduce-contract-testing Slack channel for help with this.
1. Visit the production pact broker at https://pactbroker-onelogin.account.gov.uk/
1. Find the row for the Consumer/Provider combination you're interested in
1. View its pact matrix (small grid icon)
1. Click the timestamp in the "Pact Published" column
1. Click the three dots icon and "View in API Browser"
1. Copy the JSON in the "Response Body" section
1. Save it in a file with a `.json` suffix in `lambdas/<lambda-name>/pacts`
1. Ensure the test class is annotated with `@PactFolder("pacts")` and any `@PactBroker` annotation is removed
1. Run the tests

## Code structure
The application is configured as a Gradle project with a sub-project for each Lambda. The following are the main folders and their use:
| Folder | Description |
| ------ | ----------- |
| deploy | Contains the AWS Resources such as Cloud Formation Templates and Step Function Definitions required to build and deploy the di-ipv-core-back component.
| lambdas | Source code to the Java and Node.js AWS Lambdas which come together to form di-ipv-core-back |
| lib & libs | Shared sources used by each of the Lambdas |
| openAPI | Open API Definition used by the Internal and External API Gateway |

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

## Deploy
```
sam deploy --debug --config-file ./samconfig.toml --config-env dev-{{environment}}
```

## Sync
```
sam sync --watch --config-file samconfig.toml --config-env {{environment}} --stack-name core-back-dev-{{environment}} --region eu-west-2
```

## Canaries
When deploying using dev-deploy, the canary deployment strategy which will be used is set in LambdaDeploymentPreference and StepFunctionsDeploymentPreference in template.yaml file.

When deploying using the pipeline, canary deployment strategy set in the pipeline will be used and override the default set in template.yaml.

Canary deployments will cause a rollback if any canary alarms associated with a lambda or step-functions are triggered and a slack notification will be sent to #di-ipv-core-non-prod-alarms or #di-ipv-core-prod-alarms.

To skip canaries such as when releasing urgent changes to production, set the last commit message to contain either of these phrases: [skip canary], [canary skip], or [no canary] as specified in the [Canary Escape Hatch guide](https://govukverify.atlassian.net/wiki/spaces/PLAT/pages/3836051600/Rollback+Recovery+Guidance#Escape-Hatch%3A-how-to-skip-canary-deployments-when-needed).
`git commit -m "some message [skip canary]"`

Note: To update LambdaDeploymentPreference or StepFunctionsDeploymentPreference, update the LambdaCanaryDeployment or StepFunctionsDeploymentPreference pipeline parameter in the [core-common-infra repository](https://github.com/govuk-one-login/ipv-core-common-infra/tree/main/terraform/deployments). To update the LambdaDeploymentPreference or StepFunctionsDeploymentPreference for a stack in dev using sam deploy, parameter override needs to be set in [samconfig.toml](./deploy/samconfig.toml):

`--parameter-overrides LambdaDeploymentPreference=<define-strategy> \`
`--parameter-overrides StepFunctionsDeploymentPreference=<define-strategy> \`
