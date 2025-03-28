FROM openjdk:17-jdk-slim as build

WORKDIR /core-back

RUN apt-get update && apt-get install -y findutils

COPY gradle ./gradle
COPY gradlew ./
COPY *.gradle ./

RUN ./gradlew --version

COPY lambdas ./lambdas
COPY libs ./libs
COPY local-running ./local-running

RUN --mount=type=cache,target=/root/.gradle ./gradlew :local-running:build --no-daemon
RUN mkdir untarred && tar -xvf local-running/build/distributions/local-running.tar -C ./untarred

FROM openjdk:17-jdk-slim

WORKDIR /core-back

COPY --from=build /core-back/untarred/local-running .
COPY --from=build /core-back/local-running/*.yaml .

ENV PORT 4502
EXPOSE $PORT
EXPOSE 5002

ENTRYPOINT ["./bin/local-running"]
