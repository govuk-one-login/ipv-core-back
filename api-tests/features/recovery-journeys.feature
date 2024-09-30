Feature: Recovery journeys

  Scenario: Recovery event from page state - the same page is returned
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit a 'attempt-recovery' event
    Then I get a 'page-ipv-identity-document-start' page response

  Scenario: Recovery event from CRI state - the same CRI is returned
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit a 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit a 'attempt-recovery' event
    Then I get a 'dcmaw' CRI response

  Scenario: Missing session id - pyi-timeout-recoverable returned
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit a 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub with a missing session id
    Then I get a 'pyi-timeout-recoverable' page response with a non-empty clientOAuthSessionId
    When I submit a 'build-client-oauth-response' event with no session id
    Then I get an OAuth response with error code 'access_denied'
