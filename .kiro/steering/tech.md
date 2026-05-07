# Core-back

## Runtime
- Java 21 (production Lambda runtime, `sourceCompatibility = JavaVersion.VERSION_21`)
- ARM64 (Graviton) Lambda architecture
- Lambda SnapStart enabled globally

## Build
- Gradle with version catalog (`gradle/libs.versions.toml`) for centralised dependency management
- `RepositoriesMode.FAIL_ON_PROJECT_REPOS` — all repositories declared centrally in settings.gradle
- SAM (Serverless Application Model) for packaging and deployment
- Tests are skipped during SAM builds unless `GRADLE_SAM_EXECUTE_TEST` is set
- GitHub Packages repository for `di-data-model-jackson` (requires PAT with `read:packages` — see `secrets.gradle.template`)

## Core Libraries
All versions are managed in `gradle/libs.versions.toml`. Use catalog references (e.g. `libs.lombok`) not inline versions.
- **AWS SDK v2** — DynamoDB, DynamoDB Enhanced, KMS, SQS, AppConfig. Uses URL connection client (`apache-client` is globally excluded).
- **Jackson** — JSON/YAML serialisation (`jackson-databind`, `jackson-dataformat-yaml`)
- **Log4j 2** — logging via `LogManager.getLogger()` with `StringMapMessage` for structured output
- **Powertools for AWS Lambda** — `@Logging`, `@FlushMetrics`, `@Parameters` annotations. Applied via AspectJ post-compile weaving (`io.freefair.aspectj.post-compile-weaving` plugin).
- **Lombok** — `@Getter`, `@Setter`, `@Builder`, `@Data` throughout. `lombok.config` sets `addLombokGeneratedAnnotation = true` so Lombok-generated code is excluded from JaCoCo coverage.
- **Nimbus OAuth2/OIDC SDK** — OAuth/OIDC protocol handling (token parsing, JWT validation)
- **OpenTelemetry** — distributed tracing instrumentation (trace/span IDs in structured logs)
- **di-data-model-jackson** — shared data model from `govuk-one-login/data-vocab`
- **Apache Commons** — `commons-codec`, `commons-collections4`

## Testing Libraries
- **JUnit Jupiter** (JUnit 5) — test framework with `@ExtendWith(MockitoExtension.class)`
- **Mockito** — mocking with `@Mock`/`@InjectMocks`. Uses Mockito agent JVM arg (`-javaagent:${configurations.mockitoAgent.asPath}`).
- **Hamcrest** — matchers for assertions
- **AssertJ** — fluent assertions (used alongside Hamcrest)
- **system-stubs-jupiter** — environment variable stubbing in unit tests
- **PACT** — consumer and provider contract tests. Pact broker configured for CI; local runs use `@PactFolder("pacts")`.
- **test-helpers / test-data** — shared test utilities in `/libs` (LogCollector, test fixtures)

Test environment variables are set globally in the root `build.gradle`:
`LAMBDA_TASK_ROOT=handler`, `AWS_EMF_ENVIRONMENT=Local`, `AWS_XRAY_CONTEXT_MISSING=IGNORE_ERROR`, `POWERTOOLS_METRICS_DISABLED=true`

## Code Quality
- **Spotless** — Google Java Format 1.25.2, AOSP style. Import order: `default → javax → java → static`. Also formats `.gradle` files with greclipse.
- **JaCoCo** — code coverage configured in every lambda's `build.gradle`, with XML reports for CI
- **SonarCloud** — static analysis (project: `ipv-core-back`, org: `govuk-one-login`)
- **detect-secrets** — Yelp/detect-secrets with `.secrets.baseline`
- **pre-commit** — hooks for JSON formatting, trailing whitespace, AWS credential detection, CloudFormation linting (cfn-lint), and Checkov IaC scanning

## Observability
- **Powertools** — structured logging and CloudWatch Embedded Metrics
- **OpenTelemetry** — tracing instrumentation
- **Dynatrace** — APM for non-dev environments (via Lambda layers)

# API Tests
The API tests are written in TypeScript with Cucumber. See `/api-tests/package.json` for dependencies.

# Local Running
The code in `/local-running` allows developers to run the orchestrator stub, core-front, and core-back in Docker containers on their development machines.
Uses Javalin to simulate API Gateway. The project contains code to mimic the AWS step function, so these must be kept in sync.

# Journey Map Visualiser
The journey map visualiser is written in TypeScript and uses the Mermaid framework. See `/journey-map/package.json` for dependencies.
