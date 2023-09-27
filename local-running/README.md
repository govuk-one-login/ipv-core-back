# Local running of ipv-core and the CRIs

This is an attempt at running core-front, core-back and the CRIs locally. They run in containers and are orchestrated by
docker compose. The benefits of this are quick(er) deployments and being able to get a debugger into the lambdas.

## What it's not

A replacement for deploying your stack to AWS and making sure things work properly in that environment.

## How it works

Core-front, orch-stub and the CRI stubs are pretty straight forward and just use the current Dockerfiles we have to build
images and run them.

Core-back has some extra code to replace the AWS step functions we use and the API gateways. A Spark application is spun
up with endpoints the same as the API gateways. The lamdbas are called from here, with the required inputs constructed
appropriately.

All other AWS services are still used - Dynamo, SSM, SQS etc. They're called by the lambdas as usual.

## How to use it

You need to have the core-front and stubs repos checked out and on the same level as the core-back repo.

Core-front needs a very minor code change to make things stable. It's on a branch called "local-running". Pull it before
spinning things up.

You'll need to set some SSM parameters for your env. These are mostly to set up new connections for core to the locally
running CRIs. Also one to configure the orch-stubs expected redirect URL. There is a script to set these values. You'll
need to auth to your AWS dev account (dev01 or dev02), using your favourite method. Basically make sure your AWS creds
are in your environment. Below is an example. Change the dev account and dev-env to match your setup.

You can add the `--dry-run` flag at the end to just show what params would get written. Probably worth doing the first
time.

```
aws-vault exec core-dev01 -- ./setSsmConfigForLocalOrCloudRunning.py dev-chrisw local
```

Next, spin up the containers with Docker compose. You need to have your dev env and the number of your dev account (01
or 02), set as env vars, and be auth'd to your AWS account. Here's how I do it.

```
ENVIRONMENT=dev-chrisw DEV_ACCOUNT_NUM=01 aws-vault exec core-dev01 -- docker-compose up
```

You can now visit the orch-stub at http://localhost:3000 and start a journey.

### Debugging

All of the running Java containers expose a debug port to connect to. This allows you to attach your debugger and see
what's going on. The debug port is 2000 ports above the http port the services are listening on. Look at the Docker
compose file to see which port to use for which service.

### How to get back to using your cloud deployment

You'll need to change your SSM params to set your CRI's connections back, as well as the orch-stub's expected redirect
URL. The script can do that.

```
aws-vault exec core-dev01 -- ./setSsmConfigForLocalOrCloudRunning.py dev-chrisw cloud
```

## Known limitations

The async stuff from the f2f CRI. As we're not deployed into the cloud, the process-async-cri-credential lambda isn't
hooked up to the SQS queue. I think it might be possible to fix this my adding something that runs in a background
thread that polls the queue and forwards messages on. But that doesn't exist yet.
