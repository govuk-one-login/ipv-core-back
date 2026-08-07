# Digital Identity IPV Core Back

This is the back-end code for the core of the Identity Proofing and Verification (IPV) system within the GDS digital identity platform, GOV.UK One Login.

## Related Repositories & Internal Docs

### Related Repositories
* [di-ipv-core-front](https://github.com/govuk-one-login/ipv-core-front) - Frontend code for the core of the Identity Proofing and Verification (IPV) system.
* [di-ipv-core-tests](https://github.com/govuk-one-login/ipv-core-tests) - Feature tests for the core of the Identity Proofing and Verification (IPV) system.
* [di-ipv-core-common-infra](https://github.com/govuk-one-login/ipv-core-common-infra) - Infrastructure and configuration values for the core of the Identity Proofing and Verification (IPV) system.
* [di-ipv-stubs](https://github.com/govuk-one-login/ipv-stubs) - Stubs for IPV Core dependencies (i.e. CRIs), used for testing in dev/build and occasionally higher environments.

### Repository Architecture & Documentation

Explore the subfolder documentation for details on architecture, testing, local execution, and deployment:

* [Journey Map Tool](journey-map/README.md) — Interactive web tool for visualising and navigating IPV Core state machine user journeys.
* [Journey Engine Architecture](lambdas/process-journey-event/src/main/java/uk/gov/di/ipv/core/processjourneyevent/journey-engine.md) — Dive into state machine execution logic and event processing mechanics.
* [Journey Map Syntax](lambdas/process-journey-event/src/main/java/uk/gov/di/ipv/core/processjourneyevent/journey-map-syntax.md) — Specification and syntax guide for configuring journey map state transitions.
* [Local Running Guide](local-running/README.md) — Guide for running core-back locally and debugging Java code without AWS.
* [API Tests Guide](api-tests/README.md) — Documentation for executing Cucumber integration tests.
* [Deployment Documentation](deploy/README.md) — Deployment options and guidelines for dev environments and CI pipelines.

---

## Code Structure

```
├── deploy/           # CloudFormation templates and Step Function definitions
├── lambdas/          # Java source code for AWS Lambdas
├── libs/             # Shared Java source code used across lambdas
├── local-running/    # Local application server and Docker configurations
├── api-tests/        # Integration test suite
├── journey-map/      # Web application for visualising journey transitions
└── openAPI/          # OpenAPI specifications for Core Gateways
```

---

## Development Setup

The `di-ipv-core-back` repository consists of Java-based AWS Lambdas. The following section will guide you through setting up your local environment.

### Pre-Commit Setup
We use [pre-commit](https://pre-commit.com/) to help with linting and automated formatting (JSON formatting, EOF fixes, trailing whitespace removal, credential detection, CloudFormation linter, Checkov).

If you haven't already installed pre-commit via Homebrew, run:
```bash
brew install pre-commit
```

To set up pre-commit in your local:
```bash
pre-commit install
```

To update the pre-commit plugin versions:
```bash
pre-commit autoupdate && pre-commit install
```

### GitHub Package Authentication (`secrets.gradle`)
The DI `data-vocab` classes are published to a GitHub Maven repository (https://github.com/govuk-one-login/data-vocab/packages). You require a personal access token with `read:packages` permission to download them.

1. See [Managing your personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) for creation steps.
2. Copy the `secrets.gradle.template` to `secrets.gradle`
3. Open `secrets.gradle` and fill in your GitHub username and personal access token.

---

## Building & Deploying

### Building
The application is configured as a Gradle multi-project:

```bash
./gradlew build
```

### Development Environments & Deployments
Instantiating core-back to run in a safe environment can be done using:
* [local-running](local-running/README.md) - Exposes core-back on `localhost:4502`.
* [dev-deploy tool](https://github.com/govuk-one-login/ipv-core-common-infra/blob/main/utils/dev-deploy/README.md) - Deploys a stack to your personal dev environment.
* [dev-pipeline](https://github.com/govuk-one-login/ipv-core-back/actions/workflows/secure-post-merge.yml) - Allows manual deployment (`workflow_dispatch`) of a selected branch to the shared dev environment.

---

## Testing Overview

The `di-ipv-core-back` service uses several levels of testing to ensure reliability and contract safety:

* **Unit Tests** — Each Lambda module contains unit tests that verify class functionality in isolation (`lambdas/<lambda-name>/src/test`).
* **API Tests** — Integration tests verifying core logic and user routing without frontend overhead. For detailed setup instructions, see the [API Tests Guide](api-tests/README.md).
* **Pact Tests** — Contract tests ensuring JSON request/response formats match agreements with integrated services.
* **Feature Tests** — Cucumber feature tests for end-to-end IPV Core user journeys, residing in the [di-ipv-core-tests](https://github.com/govuk-one-login/ipv-core-tests) repository (executed against deployed instances of `core-back` and `core-front`).

---

### Running Provider Pact Tests Locally

To run provider Pact tests locally, you will need a local copy of the target Pact file and an account with the Pact Broker (ask in `#introduce-contract-testing` on Slack for access):

1. Visit the production Pact Broker at [pactbroker-onelogin.account.gov.uk](https://pactbroker-onelogin.account.gov.uk/).
2. Locate the row for your Consumer/Provider combination.
3. Click the Pact Matrix icon (small grid).
4. Click the timestamp in the **Pact Published** column.
5. Click the three dots menu and select **View in API Browser**.
6. Copy the JSON from the **Response Body** section.
7. Save the JSON file inside `lambdas/<lambda-name>/pacts/` (e.g. `pact.json`).
8. Ensure your test class uses `@PactFolder("pacts")` and any `@PactBroker` annotations are temporarily removed.
9. Execute `./gradlew pactProviderTests`.

---

### Canaries

When deploying using `dev-deploy`, the canary deployment strategy used is set in `LambdaDeploymentPreference` and `StepFunctionsDeploymentPreference` in the `template.yaml` file. When deploying using the pipeline, canary deployment strategies set in the pipeline will be used and override the default set in `template.yaml`.

Canary deployments will cause a rollback if any canary alarms associated with a lambda or step-functions are triggered, and a Slack notification will be sent to `#di-ipv-core-non-prod-alarms` or `#di-ipv-core-prod-alarms`.

To skip canaries, such as when releasing urgent changes to production, set the last commit message to contain either of these phrases: `[skip canary]`, `[canary skip]`, or `[no canary]` as specified in the [Canary Escape Hatch guide](https://govukverify.atlassian.net/wiki/spaces/PLAT/pages/3836051600/Rollback+Recovery+Guidance#Escape-Hatch%3A-how-to-skip-canary-deployments-when-needed):

```bash
git commit -m "some message [skip canary]"
```

**Note:** To update `LambdaDeploymentPreference` or `StepFunctionsDeploymentPreference`, update the `LambdaCanaryDeployment` or `StepFunctionsDeploymentPreference` pipeline parameter in the [core-common-infra repository](https://github.com/govuk-one-login/ipv-core-common-infra/tree/main/terraform/deployments). To update the `LambdaDeploymentPreference` or `StepFunctionsDeploymentPreference` for a stack in dev using `sam deploy`, parameter overrides need to be set in [`samconfig.toml`](./deploy/samconfig.toml):

```bash
--parameter-overrides LambdaDeploymentPreference=<define-strategy> \
--parameter-overrides StepFunctionsDeploymentPreference=<define-strategy>
```

---
