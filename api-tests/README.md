# API tests

- This defines a suite of API tests, designed to test core's functionality without having to use the frontend.
- They are written with TypeScript and orchestrated using Cucumber.
- They can be run against a development environment or the build environment.

## Requirements

- These tests were written with node v20

## Installation

- [Create a GitHub personal access token][create-pat] with package:read scope
- Copy `.npmrc.template` to `.npmrc` and replace `GITHUB_PAT_WITH_READ:PACKAGES` with your personal access token
- Run `npm install`

## Running the tests

There are 3 presets that can be used:

- `npm run test:build` - runs against the deployed build environment
- `npm run test:local` - runs against an already-running local instance of core-back
- `npm run test:dev` - runs against a dev environment
- `npm run test:ci` - starts a new local instance of core-back and tests against it

To run a subset of the tests, add a tag before the feature(s)/scenario(s) you want to run (like in `p2-app-journey.feature`) and run them like this: `npm run test:local -- --tags @YourTag`

If you are using custom configuration, then you can use `npm test` to invoke cucumber without any presets.

### Environment variables

Env variables are provided by [dotenv][dotenv] and read from a `.env` file.
Non-secret values are stored in `.env.build` and `.env.local` for the corresponding environments.

Secret values are stored in `.env`: copy `.env.template` to `.env` and provide appropriate values.

To run against dev environments copy `.env.dev.template` to `.env.dev` and provide appropriate values.

#### Other environments

It is also possible to set up other `.env.<name>` files,
which can be selected by setting `CORE_ENV=<name>` when running the tests.

As an example, to run against a deployment in the dev01 account you could create a `.env.dev01` file something like:

```
CORE_BACK_COMPONENT_ID="https://dev-chrisw.01.dev.identity.account.gov.uk"
CORE_BACK_INTERNAL_API_URL="https://internal-test-api-dev-chrisw.01.dev.identity.account.gov.uk"
CORE_BACK_INTERNAL_API_KEY=<get from CoreBackInternalTestingApiKey secret in secrets manager>-dev-chrisw
CORE_BACK_EXTERNAL_API_URL="https://api-dev-chrisw.01.dev.identity.account.gov.uk"
CORE_BACK_PUBLIC_ENCRYPTION_KEY='{"kty":"RSA","e":"AQAB","kid":"b454ac07-e188-415d-a3c8-f1d0d38aaecd","n":"loHeaSxvMgiHStKmb-ZK5ZPpwRWrhSSQ-nTyuKQj-mYWYFNGgGGNP-37Zvzo453bUGtEeFu1zdlLAoHyT3kgs1XdqXCvPinNccpJ8lWGXcFKGRhj5jxIiIMvEBHfLs\*-cMIWW0166ndTT93ocoXdXaP64mH2iF7WWDyKqOcrVjuaUnbFbS4X2fhJwwRPj_Kin5jpJCx3MJd9eIuYyJB4CltbLTpX25oCwLw9t-p2lzHfazJSITcfTzEbOZV40fPJIR6HlJi7ApXYfAQ-dlbjMsYinFQnY6ILJXkbsjD4JXWUYaB0RbK8WTTKyehFU7P_Q8vFb7qWU4Xj9MTEHc7W3Q"}'
ORCHESTRATOR_REDIRECT_URL="https://orch-dev-chrisw.01.core.dev.stubs.account.gov.uk/callback"
JAR_SIGNING_KEY='{"kty":"EC","d":"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU","crv":"P-256","x":"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM","y":"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04"}' // pragma: allowlist secret
ASYNC_QUEUE_NAME="stubQueue_criResponseQueue_dev-chrisw"
ASYNC_QUEUE_DELAY=5
MANAGEMENT_CIMIT_STUB_API_KEY="example-value" # pragma: allowlist secret
```

## Working on the tests

- Cucumber steps are defined in `src/steps`.
- Try to create parameterised steps where possible.
- Don't create new steps unless you're sure one doesn't already exist that fits your need.
- Annotate tests with `@Build` to also be run against the build environment.

### Quality Gate Tags

All api tests should be tagged with `@QualityGateIntegrationTest`. If a test runs in our pipelines (ie in Build), and tests live features, we should tag them with `@QualityGateRegressionTest`.
If the test is for an in-development feature, we should tag it with `@QualityGateNewFeatureTest`.

Once a feature goes live, `@QualityGateNewFeatureTest` tags need to be updated to `@QualityGateRegressionTest`.
To facilitate this update, api tests for in-development work should be placed in their own feature files, if possible, so the tests can be tagged at the Feature level rather than the Scenario level.
Ideally, tests tagged with `@QualityGateNewFeatureTest` should be marked with a TODO and reference a post-go-live clean-up ticket so they can be easily identified and updated.

## IDE integration

It's a good idea to add the relevant plugins for your IDE or it will struggle to understand the structure of the project.

- For intellij use [Cucumber.js][cucumberjs]
- For VSCode use [Cucumber][cucumber]
  - You might need to configure it with:
    ```
    "cucumber.glue": [
        "api-tests/src/steps/**/*.ts"
    ]
    ```
- Or use something else you like that works, you're a grown up.

### Prettying and linting

The project is configured to use eslint for linting, and prettier for formatting. If you have pre-commit installed it will catch any issues. You can run the tests manually using:

```
npm run lint
```

And then you can fix issues automatically with

```
npm run lint-fix
```

[create-pat]: https://docs.github.com/en/enterprise-server@3.9/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-personal-access-token
[dev01-config]: https://github.com/govuk-one-login/ipv-core-common-infra/blob/main/utils/config-mgmt/app/configs/core.dev01.params.yaml#L720
[dotenv]: https://github.com/motdotla/dotenv#readme
[cucumberjs]: https://plugins.jetbrains.com/plugin/7418-cucumber-js
[cucumber]: https://marketplace.visualstudio.com/items?itemName=CucumberOpen.cucumber-official
