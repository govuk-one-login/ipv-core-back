@Build
Feature: Errors from Orchestration

  Scenario: Unrecoverable error from Orchestration
    When I start a new 'medium-confidence' journey with invalid redirect url 'https://orch.stubs.account.gov.uk/invalid-callback'
    Then I get an error from 'InitialiseIpvSession' with message 'Failed to parse the session start request' and with status code '400'

  Scenario: Recoverable error from Orchestration
    When I start a new 'medium-confidence-with-invalid-audience' journey
    Then I get a 'pyi-technical' page response
