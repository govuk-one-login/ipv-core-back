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

### Build and deploy

Build and deploy with AWS SAM CLI:

```sam build```

Deploy TBC.

### Run locally

After building with SAM, invoke the function locally:

```sam local invoke DeleteUserDataFunction```
