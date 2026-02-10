@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Recovery journeys
  Scenario: Recovery event from page state - the same page is returned
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'attempt-recovery' event
    Then I get a 'live-in-uk' page response

  Rule: Continued journey from live-in-uk page
    Background: Start journey
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit a 'appTriage' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC

    Scenario: Recovery event from CRI state - the same CRI is returned
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit a 'attempt-recovery' event
      Then I get a 'address' CRI response

    # This scenario tests cross-browser recovery for other CRIs
    Scenario: Missing ipv session id - pyi-timeout-recoverable returned
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get a 'address' CRI response
      When I clear my session id
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'pyi-timeout-recoverable' page response with a non-empty clientOAuthSessionId
      When I submit a 'build-client-oauth-response' event
      Then I get an OAuth response with error code 'access_denied'

    Scenario: User re-submits CRI callback - user is able to continue journey
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I re-submit the same request to the previous CRI stub
      Then I get a 'pyi-attempt-recovery' page response
      When I submit an 'attempt-recovery' event
      Then I get a 'fraud' CRI response
