# Local running of ipv-core and the CRIs

This is an attempt at running core-front, core-back and the CRIs locally. They run in containers and are orchestrated by
docker compose. The benefits of this are quick(er) deployments and being able to get a debugger into the lambdas.

## What it's not

A replacement for deploying your stack to AWS and making sure things work properly in that environment.

## How it works

Core-front, orch-stub, and the CRI stubs are pretty straight forward and just use the current Dockerfiles we have to build
images and run them.

Core-back has some extra code to replace the AWS step functions we use and the API gateways. A Spark application is spun
up with endpoints the same as the API gateways. The lamdbas are called from here, with the required inputs constructed
appropriately.

All other AWS services are still used - Dynamo, SSM, SQS etc. They're called by the lambdas as usual.

## How to use it

You need to have the core-front and stubs repos checked out and on the same level as the core-back repo.

You'll need to set up config and secrets for your local-running core-back,
this involves updating the params and secrets files, copying the template versions and updating any placeholders:

- `core.local.secrets.template.yaml` -> `core.local.secrets.yaml`
- `core.local.params.template.yaml` -> `core.local.params.yaml`

Values for the placeholders can be found in SSM/Secrets Manager in your dev account, or in the config repo.

If you want to run F2F journeys, you'll also need to stop the event source mapping that feeds the
process-async-cri-credential lambda. This is to allow the local deployment to read messages from the SQS queue.

There is a script to do this for you. You'll need to auth to your AWS dev account (dev01 or dev02), using your
favourite method. Basically make sure your AWS creds are in your environment. Below is an example. Change the dev
account and dev-env to match your setup.

You can add the `--dry-run` flag at the end to just show what would get written. Probably worth doing the first time.

```
aws-vault exec core-dev01 -- ./setConfigForLocalOrCloudRunning.py dev-chrisw local
```

Next, spin up the containers with Docker compose, there is a shell script to sort out some bits that vary between dev
environments. You will need to provide your dev env, the number of your dev account (01 or 02), and an AWS profile.
Here's how I do it.

```
./runLocalStack.sh -e dev-chrisw -n 01 -p core-dev01
```

You can now visit the orch-stub at http://localhost:3000 and start a journey.

### Logging

The `--attach` option in the above command will limit the logs seen in the console to just core-back's. Core-back's logs
use a specific logging configuration to display the logs in an easy-to-read way, rather than full JSON blobs.

If you want to also see the logs from core-front and the CRIs you can omit that option, but it does make the logs a lot
noisier. And JSONier.

### Debugging

All of the running containers expose a debug port to connect to. This allows you to attach your debugger and see
what's going on. The debug port is 2000 ports above the http port the services are listening on. Look at the Docker
compose file to see which port to use for which service.

### How to get back to using your cloud deployment

You'll need to change your SSM params to set your CRI's connections back, as well as the orch-stub's expected redirect
URL. The script can do that.

```
aws-vault exec core-dev01 -- ./setConfigForLocalOrCloudRunning.py dev-chrisw cloud
```

## Using local CRIs

By default, the local configuration is set up to use deployed stubs for CRIs (and CIMIT, EVCS).

To use a local version, the `core.local.params.yaml` configuration needs to be updated to point to your local instance.
This typically means updating the URLs and possibly the dev signing and encryption keys.

## Known limitations

For some reason running the functional test suite against the local deployment hangs. I do not know why.

## Future improvements

* Consolidate the setting of parameters with the dev-deploy tool.
* Integrate more fully with the dev-deploy tool to have local running as a switch within it.
* Reformat the core-front and CRI stub logs to make them easier to visually parse.
