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

RUN ./gradlew :local-running:build --no-daemon; \
    mkdir untarred; \
    tar -xvf local-running/build/distributions/local-running.tar -C ./untarred

FROM openjdk:17-jdk-slim

WORKDIR /core-back

COPY --from=build /core-back/untarred/local-running .

ENV JAVA_TOOL_OPTIONS -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005
ENV PORT 3000
EXPOSE $PORT
EXPOSE 5005

ENTRYPOINT ["./bin/local-running"]
