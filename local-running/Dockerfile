FROM amazoncorretto:21.0.7@sha256:d51610ff3c790833e308318d25424361a69680a4b7968329b73012ad502ab936 AS build

WORKDIR /core-back

RUN yum update -y && yum install -y findutils tar

COPY gradle ./gradle
COPY gradlew ./
COPY *.gradle ./

RUN ./gradlew --version

COPY lambdas ./lambdas
COPY libs ./libs
COPY local-running ./local-running

RUN --mount=type=cache,target=/root/.gradle ./gradlew :local-running:build --no-daemon
RUN mkdir untarred && tar -xvf local-running/build/distributions/local-running.tar -C ./untarred

FROM amazoncorretto:21.0.7@sha256:d51610ff3c790833e308318d25424361a69680a4b7968329b73012ad502ab936

WORKDIR /core-back

COPY --from=build /core-back/untarred/local-running .
COPY --from=build /core-back/local-running/*.yaml .

ENV PORT 4502
EXPOSE $PORT
EXPOSE 5002

ENTRYPOINT ["./bin/local-running"]
