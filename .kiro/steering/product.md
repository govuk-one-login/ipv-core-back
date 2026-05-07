# One Login
"One Login" is a service provided by the UK government to allow citizens to create a login and prove their identity once. The login can then be used to access many different government services without
the user needing to create multiple accounts.

The One Login service is made up mainly of a website and two mobile apps available on Android and iPhone. The website looks like one site to the end-user but is actually made up of multiple sites owned
by different teams and the various sites hand-off to each other as required during the user's journey.

Typically a user will start on government service's website that uses One Login. The service site (known as a relying party, or RP) will send the user to the One Login's Orchestration service which will
typically first route the user to the Authentication site to login, then Orchestration will decide where to route the user to next. If the user needs to prove or re-prove their identity they will be sent
to Identity Proving and Verification (known as IPV, or IPV Core).
Once the user has succeeded or failed in proving their identity IPV will send them back to Orchestration to continue their journey.

# IPV Core
This project; `core-back` is part of IPV Core. There is another project called `core-front` that works closely with `core-back` and contains the website that the user sees when interacting with IPV.

The main purpose of `core-back` is to route a user through the best series of pages and credential issuers (CRIs) to prove or re-prove the user's identity. Credential issuers are also part of One Login and
usually have their own web pages to guide the user through their specific UI. A credential issuer will test the user in various ways and return a signed credential to IPV core that attests to certain things
about the user. If the user was successful a credential will satisfy part of the GPG45 scoring criteria for the identity profile the user is trying to reach (https://www.gov.uk/government/publications/identity-proofing-and-verification-of-an-individual/identity-profiles).
If a credential issuer believes that a user may be fraudulent they may issue a contra-indicator. Some contra indicators are fatal to the journey and some can be mitigated by sending the user down a different
path.

IPV core uses a thing called the journey map to decide how to route a user between CRIs and eventually back to orchestration. Journey map is an overloaded term and can mean either the yaml files that
define the users' possible routes through the site or be a shorthand for the journey map visualiser which is a website that displays possible routes in a graphical form that is easier to understand than
the yaml files.

# API Surface
Core-back exposes three separate APIs defined in /openAPI:
- **Internal API** (core-back-internal.yaml) — consumed by core-front for session initialisation, CRI callbacks, and journey event processing.
- **External API** (core-back-external.yaml) — consumed by non-IPV services (e.g. Orchestration) for token exchange, user identity retrieval, and reverification.
- **Analytics API** (core-back-analytics.yaml) — consumed by observability tooling, secured with API key auth.

# Related Projects
- [ipv-core-front](https://github.com/govuk-one-login/ipv-core-front) — front end for IPV Core
- [ipv-core-tests](https://github.com/govuk-one-login/ipv-core-tests) — Cucumber feature tests run against deployed core-back + core-front
- [ipv-core-common-infra](https://github.com/govuk-one-login/ipv-core-common-infra) — shared infrastructure, Terraform deployments, and dev-deploy tooling
- [ipv-stubs](https://github.com/govuk-one-login/ipv-stubs) — stubs for CRI dependencies used in dev/build environments
- [data-vocab](https://github.com/govuk-one-login/data-vocab) — shared data model (di-data-model-jackson) consumed via GitHub Packages
