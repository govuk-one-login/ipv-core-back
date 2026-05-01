# Lambda Handler Pattern
Every handler implements `RequestHandler<InputType, Map<String, Object>>` directly — there is no base class.
Step-function-invoked lambdas use `ProcessRequest` as the input type. API-Gateway-invoked lambdas use `APIGatewayProxyRequestEvent`.

Each handler has two or three constructors:
1. **No-arg constructor** — used by the Lambda runtime. Annotated `@ExcludeFromGeneratedCoverageReport` and `@SuppressWarnings("unused")`. Creates dependencies via `ConfigService.create()` and chains to the full constructor.
2. **ConfigService constructor** (optional) — annotated `@ExcludeFromGeneratedCoverageReport`. Instantiates all services from the ConfigService.
3. **All-args constructor** — used by tests via `@InjectMocks`. Accepts all dependencies as parameters.

The `handleRequest` method is always annotated with:
```java
@Override
@Logging(clearState = true)
@FlushMetrics(captureColdStart = true)
public Map<String, Object> handleRequest(InputType event, Context context) {
```

# Dependency Injection
There is no DI framework. All injection is manual via constructors.
- `ConfigService.create()` is the factory that returns `AppConfigService` (production) or `LocalConfigService` (local running) based on the `IS_LOCAL` environment variable.
- Services are instantiated in a chain from ConfigService in the no-arg or ConfigService constructor.

# Logging
- Log4j 2 via `LogManager.getLogger()` — one static `LOGGER` per class.
- **Always use `StringMapMessage`** for structured logging, never string concatenation.
- Use `LogHelper.LogField` enum constants for field names (e.g. `LOG_MESSAGE_DESCRIPTION`, `LOG_SCORE_TYPE`).
- Call `LogHelper.attachTraceId()` and `LogHelper.attachComponentId(configService)` at the start of `handleRequest`.
- Use `LogHelper.buildErrorMessage(description, exception)` for error logging.

Example:
```java
LOGGER.info(
    new StringMapMessage()
        .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "Score threshold met")
        .with(LOG_SCORE_TYPE.getFieldName(), scoreType));
```

# Error Handling
The `handleRequest` method follows this pattern:
```java
try {
    // business logic
} catch (SpecificException e) {
    LOGGER.error(LogHelper.buildErrorMessage("Description", e));
    return new JourneyErrorResponse(JOURNEY_ERROR_PATH, statusCode, errorResponse).toObjectMap();
} catch (Exception e) {
    LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
    throw e;
}
```

Two error response patterns exist:
- **API-Gateway lambdas**: Return `JourneyErrorResponse.toObjectMap()` with HTTP status code and `ErrorResponse` enum value.
- **Step-function lambdas**: Return `StepFunctionHelpers.generateErrorOutputMap()`.

# Audit Events
- `AuditService` sends events asynchronously.
- Always call `auditService.awaitAuditEvents()` in a `finally` block when the handler uses audit.
- In tests, use `ArgumentCaptor` to verify audit event contents.

# Response Types
Handlers return `Map<String, Object>` by calling `.toObjectMap()` on domain response objects:
- `JourneyResponse` — contains a journey path (e.g. `/journey/met`)
- `JourneyErrorResponse` — contains status code, error code, and message
- `ClientResponse` — for API Gateway responses with status code and body

# Package Structure
- Base package: `uk.gov.di.ipv.core.<lambdaname>` (e.g. `uk.gov.di.ipv.core.checkgpg45score`)
- Shared library package: `uk.gov.di.ipv.core.library`
- Handler class: `<LambdaName>Handler` (e.g. `CheckGpg45ScoreHandler`)

# Test Conventions
- JUnit 5 with `@ExtendWith(MockitoExtension.class)` on every test class.
- `@Mock` for dependencies, `@InjectMocks` for the handler under test.
- Test class name: `<HandlerName>Test` in the same package under `src/test`.
- Use `ObjectMapper.convertValue()` to deserialise `Map<String, Object>` handler output into typed response classes for assertions.
- Use `LogCollector.getLogCollectorFor(HandlerClass.class)` from `libs/test-helpers` to capture and assert log output.
- Constants for test data (e.g. `TEST_SESSION_ID`, `TEST_USER_ID`) as `private static final` fields.
- Use `ProcessRequest.processRequestBuilder()` to build test inputs for step-function lambdas.

# Gradle Conventions
- All dependency versions in `gradle/libs.versions.toml` — never inline versions.
- Reference via catalog aliases: `libs.lombok`, `libs.jacksonDatabind`, `libs.bundles.awsLambda`, etc.
- Every lambda `build.gradle` includes `jacoco` plugin with `jacocoTestReport` producing XML.
- Mockito agent configured via a `mockitoAgent` configuration in each lambda's `build.gradle`.
- AspectJ post-compile weaving is applied in the parent `lambdas/build.gradle` for Powertools annotations.

# Code Coverage
- `@ExcludeFromGeneratedCoverageReport` annotation on no-arg constructors and utility classes to exclude from JaCoCo.
- Lombok's `@Generated` annotation is auto-applied (via `lombok.config`) so Lombok-generated code is excluded from coverage.

# Formatting
- Spotless enforces Google Java Format (AOSP style) — do not manually format.
- Import order: default packages → `javax` → `java` → static imports.
- Run `./gradlew spotlessApply` to auto-format before committing.
