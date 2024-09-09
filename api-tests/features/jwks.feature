@Build
Feature: JWKS endpoint
  Scenario: JWKS provides valid keys
    When I call the JWKS endpoint
    Then I get a valid JWKS response
