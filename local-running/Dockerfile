FROM amazoncorretto:21.0.8@sha256:4599af808338fc153b3d921e5e85797a477320cb677d5c672390b790159eebd1 AS build

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

FROM amazoncorretto:21.0.8@sha256:4599af808338fc153b3d921e5e85797a477320cb677d5c672390b790159eebd1

WORKDIR /core-back

COPY --from=build /core-back/untarred/local-running .
COPY --from=build /core-back/local-running/*.yaml .

ENV PORT 4502
EXPOSE $PORT
EXPOSE 5002

ENTRYPOINT ["./bin/local-running"]
