# API Tests

This defines a suite of API tests, designed to test core's functionality without having to use the frontend.

- Written with TypeScript and orchestrated using Cucumber.
- Can be run against a development environment or the build environment.

## Requirements

- Node.js v20 or higher.

## Installation

1. [Create a GitHub personal access token](https://docs.github.com/en/enterprise-server@3.9/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-personal-access-token) with `read:packages` scope.
2. Copy `.npmrc.template` to `.npmrc`
3. Replace `GITHUB_PAT_WITH_READ:PACKAGES` in `.npmrc` with your personal access token.
4. Run `npm install`.

---

## Running the Tests

### Available Presets

- `npm run test:build` - Runs against the deployed build environment.
- `npm run test:local` - Runs against an already-running local instance of core-back.
- `npm run test:dev` - Runs against a dev environment.
- `npm run test:ci` - Starts a new local instance of core-back and tests against it.

### Running a Subset of Tests

Add a tag before the feature or scenario you want to run (e.g. `@YourTag`) and execute:

```bash
npm run test:local -- --tags @YourTag
```

---

## Environment Variables

Environment variables are managed using `dotenv`.

- Non-secret values are stored in `.env.build` and `.env.local` for the corresponding environments.
- Secret values are stored in `.env` (copy `.env.template` to `.env` and fill in values).
- To run against dev environments copy `.env.dev.template` to `.env.dev` and provide appropriate values.

It is also possible to set up other `.env.<name>` files,
which can be selected by setting `CORE_ENV=<name>` when running the tests. As an example, to run against a deployment in the dev02 account you could create a `.env.dev02` with the template variables defined.

### Substituting Individual Stubs

You can run the API tests against your local or build Core setup while substituting in a single stub deployed to a developer environment. This is useful for verifying that stub changes don't break existing journeys.

To swap in a remote stub, update the relevant URLs, API keys, and signing/encryption keys in your `.env.local` or `.env.build` file.

**Example: Target a CIMIT Stub deployed in a dev environment**

- `CIMIT_STUB_BASE_URL` — e.g. `https://cimit-dev-danc.02.core.dev.stubs.account.gov.uk`
- `CIMIT_INTERNAL_API_URL` — e.g. `https://cimit-api-dev-danc.02.core.dev.stubs.account.gov.uk`
- `CIMIT_INTERNAL_API_KEY` — Internal API key of the dev environment CIMIT stub
- `MANAGEMENT_CIMIT_STUB_API_KEY` — External API key of the dev environment CIMIT stub

#### Finding Dev Environment API Keys in AWS

1. Open the AWS Console and navigate to **API Gateway > API Keys**.
2. Filter the keys using the service prefix (e.g., `cimit`).
3. Locate the correct key using the creation date or by inspecting the **Associated Stage** field on each key.

---

## Working on the Tests

- **Step Definitions:** Cucumber steps are defined in `src/steps`.
- **Parameterisation:** Write parameterised steps where possible to keep code reusable.
- **Reuse Existing Steps:** Check existing step definitions before creating new ones to avoid duplication.
- **Environment Annotation:** Annotate tests with `@Build` if they should also run against the build environment.

---

## Quality Gate Tags

All API tests must be tagged for CI routing:

- `@QualityGateIntegrationTest` - Applied to all API tests.
- `@QualityGateRegressionTest` - Tests running in Build pipelines covering live features.
- `@QualityGateNewFeatureTest` - Tests covering in-development features (should be placed in separate feature files with post-go-live clean-up tickets).

---

## Formatting and Linting

```bash
npm run lint       # Run ESLint checks
npm run lint-fix   # Automatically fix linting and formatting issues
```

---
