@Build @QualityGateIntegrationTest
Feature: P3 journeys
  Background: Enable feature sets
    Given I activate the 'disableStrategicApp' feature set

  Scenario: Only P3 in VTR results in an error
    When I start a new 'high-confidence' journey
    Then I get a 'pyi-technical' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
