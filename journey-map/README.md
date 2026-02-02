# IPV Core Journey Map

This is a small JavaScript-based tool to display the journey map in an interactive page

## Prerequisites

- Node and NPM installed

## Running the map locally

- Copy the `.env.template` file to `.env` and add the API gateway IDs and keys for any environments you want to query data from (note that production is currently used to get the default feature configuration).
  - For local dev you will need to find the ID of the API gateway hosted in relevant account. You can find this in `AWS Console / API Gateway / APIs` then copy the ID of the `IPV Core Analytics API Gateway <env>` gateway.
  - For the API Keys look in the stubs production account SSM parameter store.
- Run `npm install` to install dependencies.
- Run `npm run dev` to start the application in watch mode
- Open [http://localhost:3000] in a web browser
- Username and password are set in the `.env` file and default to `map` and `map`

### Tests

The unit tests can be run with `npm run test`, and use the vitest test runner.

The tests should run in Idea with default settings, if they don't you may need to update Idea to the latest version. (Note that you might have to use the update function in Idea multiple times to get to the latest version)

Linting and typechecking are available with `npm run lint` and `npm run tsc`.

### Build process

To build
- `npm run build` will build the frontend JavaScript into `/public`
- `npm run build-server` will build the server code into `/build`

Use `npm start` to run the built code.

In production, the journey map uses `../journey-map.Dockerfile` to run these steps.

## Running the map in a dev environment

To test the journey map deployed to AWS, it can be deployed to your dev environment.
Note that a deployed journey-map requires authentication via Google SSO. To get this working,
ask a member of the team with edit access to the `IPV Core Journey Map Link` Google Cloud Project to:

- add your journey-map dev URI as a valid redirect URI. Your dev redirect URI will take a form like `https://dev-{username}-journey-map.02.core.dev.stubs.account.gov.uk/oauth2/idresponse`.
- (optionally) add you as a principal to give you access to the project

The journey map can be deployed to your dev environment with the dev-deploy tool:

```
dev-deploy deploy -u <username> -s journey-map
```

Replace `<username>` with your dev-deploy username e.g. `theab`. For more information about the `dev-deploy` tool,
including how to set it up, see the documentation [here](https://github.com/govuk-one-login/ipv-core-common-infra/blob/main/utils/dev-deploy/README.md).

## Using the map

You should be able to pan and zoom using the mouse and scroll wheel,
as well as viewing the differences when a CRI is marked as disabled, or a particular feature flag is enabled.

You can customise analytics api request to fetch journey transitions. Currently available options are:
- Target environment:
   - Production
   - Integration
   - Staging
   - Build
   - Shared Dev
- Date and time window
- Fetch by journey id, session id or all journeys

N.B. for clarity, the map only displays states that are accessible via preconfigured entry states.

## Implementation

We run a very lightweight express server to serve the static HTML and JS,
and provide a route to expose the journey map as a JSON object.

We use an [analytics API Gateway](../openAPI/core-back-analytics.yaml) in core-back to fetch real data via Lambda endpoints:
- fetch journey transition numbers
- fetch system settings, e.g. real feature flag settings

The frontend converts this to mermaid format, and renders using two publicly available libraries:

- [mermaid-js](https://mermaid.js.org/)
- [svg-pan-zoom](https://github.com/bumbu/svg-pan-zoom)
