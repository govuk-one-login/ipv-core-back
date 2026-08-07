# Local Running of IPV Core

This is a way of running core-back (and optionally core-front and orch-stub) locally, without an AWS environment. The benefits of this are faster deployments and being able to debug core-back Java code.

## Overview

The local-running setup spins up a local web server that emulates AWS components (API Gateway and Step Functions) to execute Lambda code directly on your workstation. 

> **Limitations:** Local running is **not a replacement for deploying to AWS**. Any changes involving real AWS infrastructure (such as IAM policies, DynamoDB tables, or KMS keys) must still be deployed and verified in an AWS environment.

### Usage Options
You can run the setup in two ways (both require local configuration):
* **Core-Back only:** Ideal for executing API tests or debugging backend Java logic.
* **Core-Back, Core-Front & Orch-Stub together:** Ideal for running through full end-to-end user journeys locally via Docker Compose.

---

## Configuration

You'll need to set up config and secrets for your local-running core-back. Update the secrets files by copying the template version and populating any placeholders:

```bash
cp core.local.secrets.template.yaml core.local.secrets.yaml
```

Values for placeholders can be found in AWS Secrets Manager in your dev account or in the core-common-infra repository.

### F2F Journeys
* The async queue name should be something like `stubQueue_local_dev-joee`, matching the queue name entered in the F2F stub.
* Leave the value as the placeholder `ASYNC_QUEUE_NAME` to skip polling for async credentials.

---

## Execution

### Core-Back Only
If you only need to run a core-back process:
* Execute `./gradlew :local-running:run`
* Or set up a run configuration in your IDE that executes the Gradle task.

This is useful if you are only running the API tests, or are running orch-stub and core-front independently.

Core-back will listen on `http://localhost:4502` (for both internal and external APIs).

### Core-Back, Core-Front, and Orch-Stub Together
To spin up minimal resources to run through a journey:

1. Copy the Docker Compose template `compose.yaml.template` file and name it `compose.yaml`.
2. Modify container build paths in `compose.yaml` if your machine's directory layout differs from `dev-deploy`. 
3. Start the containers:
   ```bash
   docker-compose up
   ```
   *(To rebuild containers, pass `--build` or build a target container: `docker-compose build core-back`)*.

#### Running Endpoints
* **Orch-Stub**: `http://localhost:4500`
* **Core-Front**: `http://localhost:4501`
* **Core-Back**: `http://localhost:4502`

---

## Logging & Debugging

* **Isolated Logs**: Pass `--attach core-back` to `docker-compose up` to restrict console output to core-back's readable, non-JSON logs.
* **Remote Debugging**: Running containers expose specific debug ports for local attachment. Refer to `compose.yaml` for the exact host-to-container debug port mappings for each service (e.g., core-back, core-front, orch-stub).

---

## Using Local Stubs

By default, local running uses deployed CRI stubs. 

To point to stubs in a specific developer environment, update `core.local.params.yaml` and `core.local.secrets.yaml` with the target dev environment URLs and API keys.

#### Finding Dev Environment API Keys
1. Open the AWS Console and navigate to **API Gateway > API Keys**.
2. Filter keys using the target service prefix (e.g. `cimit`).
3. Locate the correct key using the creation date or by inspecting the **Associated Stage** field.