@Build @IntegrationTest
Feature: Well-known endpoints
  Scenario: JWKS endpoint provides valid keys
    When I call the JWKS endpoint
    Then I get a valid JWKS response

  Scenario: DID endpoint provides valid keys
    When I call the DID endpoint
    Then I get a valid DID response
