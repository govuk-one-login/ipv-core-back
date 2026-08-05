# IPV Core Journey Map

An interactive JavaScript based tool for visualising and navigating IPV Core state machine user journeys.

---

## Prerequisites & Local Setup

* **Node & NPM:** Ensure Node and NPM are installed.

### Configuration
Copy `.env.template` to `.env` and configure your credentials

Populate `.env` with API Gateway IDs and keys for target environments (Note: Production is used by default for feature configuration)
* **API Gateway IDs:** Find under `AWS Console > API Gateway > APIs` and copy the ID for `IPV Core Analytics API Gateway <env>`.
* **API Keys:** Retrieve from the SSM Parameter Store in the stubs production account.
* **Basic Auth:** Default local credentials are set in `.env` (`map` / `map`).

### Running Locally
```bash
npm install        # Install dependencies
npm run dev        # Start development server with hot-reload
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Development & Building

### Testing & Quality Checks
* `npm run test` — Run unit tests using Vitest.
* `npm run lint` — Run ESLint checks.
* `npm run tsc` — Execute TypeScript type checking.

### Build & Run
```bash
npm run build         # Build client bundle into /public
npm run build-server  # Build server source into /build
npm start             # Start the production server
```
*(Production builds use `../journey-map.Dockerfile` to containerise these steps).*

---

## Deployment to Development Environment

Deploy the journey map tool to an AWS developer environment using `dev-deploy`:

```bash
dev-deploy deploy -u <username> -s journey-map
```

> **Google SSO Requirement:** Deployed instances require Google SSO authentication. Ask an administrator with edit access to the [IPV Core Journey Map Google Cloud Project](https://console.cloud.google.com/welcome?project=ipv-core-journey-map-link) to:
> 1. Add your dev redirect URI (e.g. `https://dev-{username}-journey-map.02.core.dev.stubs.account.gov.uk/oauth2/idresponse`).
> 2. Add your account to the `Identity-IPV-Core` Google Group.

For details on setting up `dev-deploy`, see the [ipv-core-common-infra documentation](https://github.com/govuk-one-login/ipv-core-common-infra/blob/main/utils/dev-deploy/README.md).

---

## Using the Map

* **Feature Controls:** Toggle CRIs on/off or enable specific feature flags to inspect journey variations.
* **Analytics Filters:** Customise requests via the Analytics API to fetch transition data:
  * **Target Environments:** Production, Integration, Staging, Build, or Shared Dev.
  * **Time Window:** Filter by specific date/time ranges.
  * **Filter Query:** Fetch transitions by journey ID, session ID, or all journeys.

*(Note: The map renders states accessible via preconfigured entry states).*

---

## Technical Architecture

* **Server:** Lightweight Express server providing static HTML/JS assets and exposing a JSON route for the journey map.
* **Backend Ingestion:** Uses the [Core Back Analytics API Gateway](../openAPI/core-back-analytics.yaml) and Lambdas to query live transition metrics and AppConfig settings.
* **Frontend Rendering:** Converts journey logic into Mermaid format and renders using:
  * [mermaid-js](https://mermaid.js.org/) — Diagram rendering.
  * [svg-pan-zoom](https://github.com/bumbu/svg-pan-zoom) — Viewport interaction.