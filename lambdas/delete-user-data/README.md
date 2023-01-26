### Linter

Lint the code with eslint+prettier:

```npm run lint```

Fix issues that can be fixed automatically:

```npm run lint:fix```

The rules are defined in `.eslintrc` and can be customised. Includes recommended rulesets from eslint, typescript and prettier for formatting, and a jest plugin for the test files.

`.editorconfig` is also used to enforce formatting across developer machines. The EditorConfig plugin is available in most IDEs. To ensure this works it's recommended to open your IDE at the root of this directory rather than a higher level.

### Tests

Run tests with Jest:

```npm run test```

This uses `esbuild-jest` to transpile and run the tests on the fly. Note it will not fail on compilation errors so rely on your IDE to highlight any.

In VSCode you can use an extension such as "Jest Runner" to run and debug individual tests within the IDE.

### Build and invoke locally

Build via AWS SAM CLI:

```npm run build```

Invoke the function locally with the sample SNS event:

```npm run local-invoke``

### Deploy

To build and deploy to the build env, run the script from the `deploy-delete-user-data` directory where the template lives:

```aws-vault exec <core-build-profile> -- sh ./deploy.sh```
