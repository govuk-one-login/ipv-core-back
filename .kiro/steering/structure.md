# Core-back
Core-back is made up of Java AWS lambdas and shared library projects. All lambdas are Java — there are no Node.js lambdas.
Each lambda has its own Gradle sub-project in /lambdas with its own unit tests. Lambdas that communicate with other parts of One Login also have contract tests using the PACT framework.

## Step Function
The journey engine step function (/deploy/journeyEngineStepFunction.asl.json) orchestrates the core routing loop. It avoids double-billing by invoking lambdas directly rather than having one lambda call another.
The flow is: ProcessJourneyEvent → Choice → [specific lambda] → if result contains `/journey/*`, loop back to ProcessJourneyEvent; otherwise succeed.
The step-function-invoked lambdas are: CheckExistingIdentity, ResetSessionIdentity, BuildCriOauthRequest, BuildClientOauthResponse, CheckGpg45Score, CallDcmawAsyncCri, CheckReverificationIdentity, ProcessCandidateIdentity.
Every lambda task has SnapStart retry logic (5 retries with backoff for `SnapStartNotReadyException`).

## Lambdas (/lambdas)
Key lambdas include:
- process-journey-event — the state machine engine that routes users through the journey map
- initialise-ipv-session — creates new IPV sessions from orchestration requests
- build-cri-oauth-request / process-cri-callback — CRI OAuth flow (outbound and return)
- build-client-oauth-response — builds the OAuth response back to orchestration
- build-user-identity / build-proven-user-identity-details — assembles user identity from credentials
- issue-client-access-token — OAuth token exchange
- check-existing-identity / check-gpg45-score / process-candidate-identity — identity evaluation
- user-reverification / check-reverification-identity — reverification flow used for MFA reset (not identity reproving)

## Shared Libraries (/libs)
Library sub-projects:
- common-services — core domain objects (ProcessRequest, ErrorResponse, JourneyResponse, JourneyErrorResponse), config (ConfigService, AppConfigService), persistence, helpers (LogHelper, RequestHelper), exceptions (~30 exception classes), and annotations (@ExcludeFromGeneratedCoverageReport)
- audit-service — async audit event sending (AuditService)
- verifiable-credentials — VC parsing and validation
- gpg45-evaluator — GPG45 profile scoring
- cri-api-service, cri-checking-service, cri-storing-service, cri-response-service — CRI interaction layers
- user-identity-service, oauth-key-service — domain services
- ais-service, cimit-service, sis-service, evcs-service, ticf-cri-service — external service clients
- test-helpers, test-data — shared test utilities (LogCollector, test fixtures)

Note: The /lib directory contains only stale build output and is not an active source directory. Only /libs has source code.

## APIs (/openAPI)
Three OpenAPI specs define core-back's API surface:
- core-back-internal.yaml — Internal API consumed by core-front (session init, CRI callbacks, journey events). Uses Lambda proxy integration.
- core-back-external.yaml — External API for non-IPV services (token exchange, user-identity, reverification). Uses Lambda proxy integration.
- core-back-analytics.yaml — Analytics API with API key auth for observability tooling.

## Deployment (/deploy)
- template.yaml — SAM/CloudFormation template defining all Lambda functions, API Gateways, DynamoDB tables, and the step function
- samconfig.toml — per-developer and per-environment SAM deployment configs
- journeyEngineStepFunction.asl.json — step function definition (see above)
- Canary/linear deployment preferences are configurable per environment via pipeline parameters

## CI/CD (/.github)
9 GitHub Actions workflows:
- pre-merge-checks.yml — PR gate (unit tests, SAM build, secret detection, spotless check)
- secure-post-merge.yml — deployment pipeline via devplatform-upload-action with code signing
- contract-tests.yaml — PACT contract test runs
- automated-tests.yaml — reusable workflow for API tests
- secure-pipeline-api-tests-image.yml — builds API test Docker image
- journey-map.yml / journey-map-tests.yml — journey map visualiser CI
- validate-template.yml — CloudFormation template validation
- link-workflows.yaml — workflow linking

PR template (/.github/pull_request_template.md) uses Jira PYIC-XXXX ticket references and includes checklists for documentation, tests, PII exposure, and canary deployment considerations.
CODEOWNERS: `@govuk-one-login/core-team` and `@govuk-one-login/identity-sre`.
Dependabot is configured for Gradle, npm (api-tests and journey-map), and GitHub Actions dependencies.

# API Tests
The API tests (/api-tests) exercise core-back through its APIs with core-front and the credential issuers. Written in TypeScript with Cucumber.
They are run in the build pipelines and can also be run on a development machine using the local running project.

# Local Running
The code in /local-running allows developers to run the orchestrator stub, core-front, and core-back in Docker containers on their development machines.
It uses Javalin to simulate API Gateway and contains code to mimic the AWS step function, so these must be kept in sync with the real step function definition.
The locally running core can be used to run the API tests or run through the site manually. By default local-running will call out to the CRI stubs running on AWS if a CRI is needed.

# Journey Map Visualiser
The journey map visualiser (/journey-map) is a website written in TypeScript that uses the Mermaid framework to graphically render the contents
of the journey map yaml files (found in /lambdas/process-journey-event/src/main/resources/statemachine/journey-maps).
