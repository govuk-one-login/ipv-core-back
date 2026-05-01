Technology Stack (tech.md) - Documents your chosen frameworks, libraries, development tools, and technical constraints. When Kiro suggests implementations, it will prefer your established stack over alternatives.

# Core-back
Core-back is written in Java and built with Gradle.
The main libraries used by core-back are
- awsSdk
- jackson
- log4j
- powertools

For testing we use
- mockito
- hamcrest
- pact

Code formatting is checked with spotless

# API Tests
The API tests are written in typescript and cucumber. See /api-tests/package.json for dependencies

# Local Running
The code in /local-running allows developers to run the orchestrator stub, core-front, and core-back in docker containers on their development machines.
The project contains code to mimic the AWS step function on the real site, so these two need to be kept in sync.

# Journey Map Visualiser
The journey map visualiser is written in TypeScript and uses the Mermaid framework. See /journey-map/package.json for more dependencies