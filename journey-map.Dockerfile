# Dockerfile for journey map deployment
# This must be in the root directory so it can access the journey map files in ./lambdas/process-journey-event
FROM node:22.14.0-alpine3.21@sha256:9bef0ef1e268f60627da9ba7d7605e8831d5b56ad07487d24d1aa386336d1944 AS builder
WORKDIR /app

# Install packages
COPY journey-map/package.json ./
COPY journey-map/package-lock.json ./
COPY journey-map/.npmrc ./
RUN npm ci

# Copy public assets
COPY journey-map/public ./public

# Build code
COPY journey-map/src ./src
COPY journey-map/server ./server
COPY journey-map/tsconfig.json ./
COPY journey-map/tsconfig.server.json ./
RUN npm run build
RUN npm run build-server

# Prune non-production dependencies
RUN npm ci --omit=dev

FROM node:22.14.0-alpine3.21@sha256:9bef0ef1e268f60627da9ba7d7605e8831d5b56ad07487d24d1aa386336d1944 AS final
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

RUN ["apk", "--no-cache", "upgrade"]
RUN ["apk", "add", "--no-cache", "tini", "curl"]
USER appuser:appgroup

WORKDIR /app
# Copy in compile assets and deps from build container
COPY --chown=appuser:appgroup --from=builder /app/node_modules ./node_modules
COPY --chown=appuser:appgroup --from=builder /app/public ./public
COPY --chown=appuser:appgroup --from=builder /app/build ./build
COPY --chown=appuser:appgroup --from=builder /app/package.json ./
COPY --chown=appuser:appgroup --from=builder /app/package-lock.json ./

# Copy in journey maps
COPY --chown=appuser:appgroup lambdas/process-journey-event/src/main/resources/statemachine/journey-maps /app/journey-maps

ENV PORT 8080
EXPOSE 8080

ENTRYPOINT ["sh", "-c", "tini npm run start-build"]
