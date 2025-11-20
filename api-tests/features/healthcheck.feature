@Build @IntegrationTest
Feature: Healthcheck API
  Scenario: Healthcheck passes
    When I call the healthcheck endpoint
    Then the healthcheck is successful
