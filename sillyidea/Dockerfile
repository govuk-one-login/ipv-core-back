FROM openjdk:17.0.2-jdk as build

WORKDIR /coreback

COPY lambdas ./lambdas
COPY libs ./libs
COPY sillyidea ./sillyidea
COPY gradle ./gradle
COPY gradlew ./
COPY build.gradle ./
COPY settings.gradle ./

ENV PORT 3000
EXPOSE $PORT
EXPOSE 5005

RUN ./gradlew :sillyidea:build --no-daemon

ENTRYPOINT ["sillyidea/run.sh"]
