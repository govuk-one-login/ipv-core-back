FROM node:20.14-slim

RUN apt update && \
    apt upgrade -y && \
    apt install -y awscli jq curl && \
    apt clean

COPY api-tests /api-tests
COPY api-tests/secure-pipeline/run-tests.sh /
COPY openAPI /openAPI

WORKDIR /api-tests

ARG GITHUB_PAT

RUN cp .npmrc.template .npmrc && \
    sed -i s/GITHUB_PAT_WITH_READ:PACKAGES/${GITHUB_PAT}/ .npmrc && \
    npm ci && \
    rm .npmrc && \
    cp .env.template .env

ENTRYPOINT ["/run-tests.sh"]
