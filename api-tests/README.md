# API tests

- This defines a suite of API tests, designed to test core's functionality without having to use the frontend.
- They are written with TypeScript and orchestrated using Cucumber.
- They can be run against a development environment or the build environment.
- They will run in GHA as part of the pre-merge checks.

## Requirements

- These tests were written with node v20

## Installation

- [Create a GitHub personal access token][create-pat] with package:read scope
- Copy `.npmrc.template` to `.npmrc` and replace `GITHUB_PAT_WITH_READ:PACKAGES` with your personal access token
- Run `npm install`

## Running the tests

Tags are optional

```
    npm test -- --tags '@Build'
```

### Environment variables

- Env variables are provided by [dotenv][dotenv] and read from a `.env` file.
- Copy `.env.template` to `.env` and provide values for your dev env (see below for an example)
- You can comment out the build env values and have a new block for you dev env. This makes it easy to switch between the two.

As an example, to run against a deployment in the dev01 account you could set your env vars as below:

The value for `CORE_BACK_INTERNAL_API_KEY` has your dev-env appended to the end. This is because API keys must be unique in an account.
The value for `CORE_BACK_PUBLIC_ENCRYPTION_KEY` for the dev environments can be found in [the dev config files][dev02-config] under `ORCHESTRATOR_DEFAULT_JAR_ENCRYPTION_PUBLIC_KEY`. It'll need base64 decoding.
The value for `JAR_SIGNING_KEY` will probably be the same as for the build env.

- CORE_BACK_COMPONENT_ID="https://dev-chrisw.01.dev.identity.account.gov.uk"
- CORE_BACK_INTERNAL_API_URL="https://internal-test-api-dev-chrisw.01.dev.identity.account.gov.uk"
- CORE_BACK_INTERNAL_API_KEY=<get from CoreBackInternalTestingApiKey secret in secrets manager>-dev-chrisw
- CORE_BACK_EXTERNAL_API_URL="https://api-dev-chrisw.01.dev.identity.account.gov.uk"
- CORE_BACK_PUBLIC_ENCRYPTION_KEY='{"kty":"RSA","e":"AQAB","kid":"b454ac07-e188-415d-a3c8-f1d0d38aaecd","n":"loHeaSxvMgiHStKmb-ZK5ZPpwRWrhSSQ-nTyuKQj-mYWYFNGgGGNP-37Zvzo453bUGtEeFu1zdlLAoHyT3kgs1XdqXCvPinNccpJ8lWGXcFKGRhj5jxIiIMvEBHfLs\*-cMIWW0166ndTT93ocoXdXaP64mH2iF7WWDyKqOcrVjuaUnbFbS4X2fhJwwRPj_Kin5jpJCx3MJd9eIuYyJB4CltbLTpX25oCwLw9t-p2lzHfazJSITcfTzEbOZV40fPJIR6HlJi7ApXYfAQ-dlbjMsYinFQnY6ILJXkbsjD4JXWUYaB0RbK8WTTKyehFU7P_Q8vFb7qWU4Xj9MTEHc7W3Q"}'
- ORCHESTRATOR_REDIRECT_URL="https://orch-dev-chrisw.01.core.dev.stubs.account.gov.uk/callback"
- JAR_SIGNING_KEY='{"kty":"EC","d":"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU","crv":"P-256","x":"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM","y":"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04"}' // pragma: allowlist secret

## Working on the tests

- Cucumber steps are defined in `src/steps`.
- Try to create parameterised steps where possible.
- Don't create new steps unless you're sure one doesn't already exist that fits your need.

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
[dev02-config]: https://github.com/govuk-one-login/ipv-core-common-infra/blob/main/utils/config-mgmt/app/configs/core.dev01.params.yaml#L720
[dotenv]: https://github.com/motdotla/dotenv#readme
