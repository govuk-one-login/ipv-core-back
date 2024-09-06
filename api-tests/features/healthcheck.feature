@Build
Feature: Healthcheck API
  Scenario: Healthcheck passes
    Given I call the healthcheck endpoint
    Then the healthcheck is successful
