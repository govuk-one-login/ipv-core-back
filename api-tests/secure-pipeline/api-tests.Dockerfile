FROM node:22.14-slim

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
