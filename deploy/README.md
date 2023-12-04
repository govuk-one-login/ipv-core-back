# Deploy

## Developer Deployment

You can deploy yourself a stack into the development account using the following steps!
Alternatively you can use the [Developer Environment Deployment Tool](https://github.com/govuk-one-login/ipv-core-common-infra/tree/main/utils/dev-deploy).

### SAM Config

Modify and add the following snippet into `deploy/samconfig.toml`. The defines all the parameters that will be used by the `sam deploy` command we'll be using shortly.

```sh
[dev-<your-name>.deploy.parameters]
stack_name = "<your-name>-core-back-stack"
s3_bucket = "aws-sam-cli-managed-default-samclisourcebucket-ec647gpjuo2w"
s3_prefix = "<your-name>-core-back-stack"
region = "eu-west-2"
capabilities = "CAPABILITY_IAM"
parameter_overrides = "Environment=\"dev-<your-name>\""
```

### SAM Build

[sam build](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-build.html) will convert the template.yaml and build all the lambdas ready to be uploaded to S3 during the deployment phase

```sh
gds aws di-ipv-dev -- sam build -t template.yaml
```

### SAM Deploy

[sam deploy](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-deploy.html) will upload the artifacts built during the `sam build` phase. It'll then create a changeset and deploy any changes into AWS.

```sh
gds aws di-ipv-dev -- sam deploy --config-file samconfig.toml --config-env dev-<your-name>
```
