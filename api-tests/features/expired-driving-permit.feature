@Build @QualityGateIntegrationTest @QualityGateNewFeatureTest
Feature: Expired DCMAW/Async DCMAW Driving Permits
  Scenario: An expired DCMAW driving permit and current date is past the grace period should result in identity reprove
    # This creates a DCMAW Async VC which has nbf 26/07/2022
    Given the subject already has the following expired credentials
      | CRI            | scenario                       |
      | dcmawAsync     | kenneth-driving-permit-expired |
    And the subject already has the following credentials
      | CRI            | scenario                       |
      | drivingLicence | kenneth-driving-permit-valid   |
      | address        | kenneth-current                |
      | fraud          | kenneth-score-2                |

    Given I activate the 'disableStrategicApp' feature set
    And I start a new 'medium-confidence' journey
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: An expired DCMAW driving permit but the current date is not past the grace period should result in identity reuse
    # Initial journey proving with expired driving licence in app
    Given I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
    # This step will enqueue a VC with NBF set to whenever this test is ran. This
    # means that, at reuse, the test will always be within the grace period.
    When the async DCMAW CRI produces a 'kenneth-driving-permit-expired' VC
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
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    # New journey
    When I start a new 'medium-confidence' journey
    Then I get an 'page-ipv-reuse' page response
