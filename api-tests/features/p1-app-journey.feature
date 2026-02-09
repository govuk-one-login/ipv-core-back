@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: P1 app journey
  Scenario: P1 App Journey
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
    When the async DCMAW CRI produces a 'kennethD' 'drivingPermit' 'success' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity
