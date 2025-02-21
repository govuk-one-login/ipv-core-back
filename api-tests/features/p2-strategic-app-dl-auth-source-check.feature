@Build @InitialisesDCMAWSessionState
Feature: M2B Strategic App Journeys with DL authoritative source check

  Background: Get to the DL check
    Given I activate the 'strategicApp,drivingLicenceAuthCheck' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
    When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response

  Scenario: Successful auth check qqqqqq
    When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: Auth check access_denied qqqq
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
    When I submit a 'next' event

    # Attempt 1 - retry after viewing prove-identity-another-way
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
    When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
    When I submit an 'end' event
    Then I get a 'prove-identity-another-way' page response
    When I submit an 'anotherTypePhotoId' event

    # Attempt 2 - give up
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
    When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
    When I submit an 'end' event
    Then I get a 'prove-identity-another-way' page response
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

  Scenario: CI on auth check asks for alternative document qqqq
    When I submit 'kenneth-driving-permit-needs-alternate-doc' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'pyi-driving-licence-no-match-another-way' page response
    When I submit a 'end' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity