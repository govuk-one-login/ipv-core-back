FROM node:24.19.0-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03

RUN apt update && \
    apt upgrade -y && \
    apt install -y awscli jq curl && \
    apt clean

COPY api-tests /api-tests
COPY api-tests/secure-pipeline/run-tests.sh /
COPY openAPI /openAPI

WORKDIR /api-tests

ARG GITHUB_PAT

RUN npm ci && \
    cp .env.template .env

ENTRYPOINT ["/run-tests.sh"]
