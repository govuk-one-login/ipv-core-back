# Local running of ipv-core

This is a way of running core-back (and optionally core-front and orch-stub) locally, without an AWS environment.
The benefits of this are quick(er) deployments and being able to debug the core-back Java code.

## What it's not

A replacement for deploying your stack to AWS and making sure things work properly in that environment.
In particular, any changes that involve changes to real AWS resources should be deployed and tested in AWS.

## How it works

Core-back normally runs distributed across multiple AWS components (API Gateway, Step Function and Lambda).
Instead, the local-running app runs a web-server with some extra code to replace those AWS resources and execute
the lambda code directly.

## How to use it

There are two ways of using the local-running setup, but both require setting up appropriate configuration.

### Configuration

You'll need to set up config and secrets for your local-running core-back,
this involves updating the secrets files, copying the template version and updating any placeholders:

- `core.local.secrets.template.yaml` -> `core.local.secrets.yaml`

Values for the placeholders can be found in Secrets Manager in your dev account, or in the config repo.

### F2F journeys

The async queue name should be something like `stubQueue_local_dev-joee`,
and this should match the queue name you enter in the F2F stub.

Leave the value as the placeholder `ASYNC_QUEUE_NAME` to skip polling for async credentials.

### Core-back only

If you only need to run a core-back process, then you can run directly as a gradle task:
- `./gradlew :local-running:run`
- or set up a run configuration in your IDE that executes the gradle task

This might be useful if you are only running the API tests, or are running orch-stub and core-front independently.

Core-back will now be running on http://localhost:4502 (for both internal and external APIs).

### Core-back, Core-front and Orch-stub together

This allows you to run minimal resources to actually run through a journey.

You need to have the `ipv-core-front` and `ipv-stubs` repos checked out and on the same level as the core-back repo,
as well as the configuration described above.

Next, spin up the containers with Docker compose: `docker-compose up`.

If you need to rebuild containers, either pass `--build` to the docker-compose command,
or build a specific container: `docker-compose build core-back`

You can now visit the orch-stub at http://localhost:4500 and start a journey.
Core-front will run on http://localhost:4501 and core-back will run on http://localhost:4502.

### Logging

The `--attach` option in the above command will limit the logs seen in the console to just core-back's. Core-back's logs
use a specific logging configuration to display the logs in an easy-to-read way, rather than full JSON blobs.

If you want to also see the logs from core-front and the CRIs you can omit that option, but it does make the logs a lot
noisier. And JSONier.

### Debugging

All of the running containers expose a debug port to connect to. This allows you to attach your debugger and see
what's going on. The debug port is 2000 ports above the http port the services are listening on. Look at the Docker
compose file to see which port to use for which service.

## Using local CRIs

By default, the local configuration is set up to use deployed stubs for CRIs (and CIMIT, EVCS).

To use a local version, the `core.local.params.yaml` configuration needs to be updated to point to your local instance.
This typically means updating the URLs and possibly the dev signing and encryption keys.

## Future improvements

* Consolidate the setting of parameters with the dev-deploy tool.
* Integrate more fully with the dev-deploy tool to have local running as a switch within it.
* Reformat the core-front and CRI stub logs to make them easier to visually parse.
