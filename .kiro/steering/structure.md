Project Structure (structure.md) - Outlines file organization, naming conventions, import patterns, and architectural decisions. This ensures generated code fits seamlessly into your existing codebase.


# Core-back
Core-back is made up of a number of separate AWS lambdas. Each lambda has its own project, and there is also a common library project for shared code. These projects
are found in /lambdas and /libs and are written in Java.
Each project has its own unit tests, and lambdas that communicate with other parts of One Login also have contract tests using the PACT framework.
Sometimes a lambda needs to call another lambda before returning control to core-front. To avoid being charged double for the time spent in the second lambda the lambdas are
invoked by an AWS step function that is defined in /deploy/journeyEngineStepFunction.asl.json

# API Tests
The API tests exercise core-back through it's APIs with core-front and the credential issuers. They are run in the build pipelines and can also be run on a development machine
using the local running project.

# Local Running
The code in /local-running allows developers to run the orchestrator stub, core-front, and core-back in docker containers on their development machines.
The locally running core can be used ot run the API tests or run through the site manually. By default local-running will call out to the CRI stubs running on AWS if a CRI is needed.

# Journey Map Visualiser
The journey map visualiser is found in the /journey-map folder. It is a website written in TypeScript that uses the Mermaid framework to graphically render the contents
of the journey map yaml files (found in /lambdas/process-journey-event/src/main/resources/statemachine/journey-maps).