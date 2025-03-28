FROM amazoncorretto:21.0.6-al2@sha256:c0643148d077b3917bf6c085aaa1ac35ff1f202344ab8691cc0f5953f9b97f8e AS build

WORKDIR /core-back

RUN yum update && yum install -y findutils tar

COPY gradle ./gradle
COPY gradlew ./
COPY *.gradle ./

RUN ./gradlew --version

COPY lambdas ./lambdas
COPY libs ./libs
COPY local-running ./local-running

RUN --mount=type=cache,target=/root/.gradle ./gradlew :local-running:build --no-daemon
RUN mkdir untarred && tar -xvf local-running/build/distributions/local-running.tar -C ./untarred

FROM amazoncorretto:21@sha256:c0643148d077b3917bf6c085aaa1ac35ff1f202344ab8691cc0f5953f9b97f8e

WORKDIR /core-back

COPY --from=build /core-back/untarred/local-running .
COPY --from=build /core-back/local-running/*.yaml .

ENV PORT 4502
EXPOSE $PORT
EXPOSE 5002

ENTRYPOINT ["./bin/local-running"]
