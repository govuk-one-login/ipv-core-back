@Build @IntegrationTest
Feature: Errors from Orchestration

  Scenario: Unrecoverable error from Orchestration
    When I start a new 'medium-confidence-invalid-redirect-uri' journey with invalid redirect uri
    Then I get an error from 'InitialiseIpvSession' with message 'Failed to parse the session start request' and with status code '400'

  Scenario: Recoverable error from Orchestration
    When I start a new 'medium-confidence-with-invalid-audience' journey
    Then I get a 'pyi-technical' page response
    When I submit a 'next' event
    Then I get an OAuth response with error code 'invalid_grant'
