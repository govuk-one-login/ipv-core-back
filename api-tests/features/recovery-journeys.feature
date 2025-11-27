@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Recovery journeys
  Background: Disable the strategic app
    Given I activate the 'disableStrategicApp' feature set

  Scenario: Recovery event from page state - the same page is returned
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'attempt-recovery' event
    Then I get a 'live-in-uk' page response

  Scenario: Recovery event from CRI state - the same CRI is returned
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit a 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit a 'attempt-recovery' event
    Then I get a 'dcmaw' CRI response

  # This scenario tests cross-browser recovery
  # When a user switches to a different browser when returning from DCMAW (e.g. because they
  # started the journey from they non-default browser), they lose their session id
  Scenario: Missing ipv session id - pyi-timeout-recoverable returned
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit a 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I clear my session id
    And I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get a 'pyi-timeout-recoverable' page response with a non-empty clientOAuthSessionId
    When I submit a 'build-client-oauth-response' event
    Then I get an OAuth response with error code 'access_denied'

  Scenario: User submits CRI callback for wrong CRI - user is able to continue journey
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit a 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I re-submit the same request to the previous CRI stub
    Then I get a 'pyi-attempt-recovery' page response
    When I submit an 'attempt-recovery' event
    Then I get a 'page-dcmaw-success' page response
