#!/bin/bash
# Creates Chainguard GitHub identities with libraries.java.pull role
# for pulling Java libraries from libraries.cgr.dev in GitHub Actions workflows.
# Can be used as a base for any govuk-one-login repo.

chainctl iam identities create github ipv-core-back \
  --parent digital.cabinet-office-gov.uk \
  --description "ipv-core-back main" \
  --role libraries.java.pull \
  --github-repo govuk-one-login/ipv-core-back \
  --github-ref refs/heads/main \
  --github-audience https://issuer.enforce.dev

# No --github-ref specified: matches any branch/ref
chainctl iam identities create github ipv-core-back-testing \
  --parent digital.cabinet-office-gov.uk \
  --description "ipv-core-back testing" \
  --role libraries.java.pull \
  --github-repo govuk-one-login/ipv-core-back \
  --github-audience https://issuer.enforce.dev
