@Build @InitialisesDCMAWSessionState @IntegrationTest
Feature: Strategic App Retry Journeys
  Background: Trying again goes directly to the correct download page
    Given I activate the 'strategicApp,drivingLicenceAuthCheck' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response

  Scenario Outline: Trying again with a mobile device goes directly to the correct download page
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an '<device-type>' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context '<device-type>'
    When the async DCMAW CRI produces a 'kenneth-changed-family-name-driving-permit-valid' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
    When I submit a 'next' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context '<device-type>'

    Examples:
      | device-type |
      | iphone      |
      | android     |

  Scenario Outline: Trying again with a desktop device goes directly to the correct download page
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit an '<device-type>' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context '<device-type>'
    When the async DCMAW CRI produces a 'kenneth-changed-family-name-driving-permit-valid' VC
    And I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
    When I submit a 'next' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context '<device-type>'

    Examples:
      | device-type |
      | iphone      |
      | android     |

  Scenario Outline: Trying again with a mobile device app only goes directly to the correct download page
    When I submit a 'international' event
    Then I get a 'non-uk-passport' page response
    When I submit a 'next' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an '<device-type>' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context '<device-type>-appOnly'
    When the async DCMAW CRI produces a 'kenneth-changed-family-name-driving-permit-valid' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
    When I submit a 'next' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context '<device-type>-appOnly'

    Examples:
      | device-type |
      | iphone      |
      | android     |

  Scenario Outline: Trying again with a desktop device app only goes directly to the correct download page
    When I submit a 'international' event
    Then I get a 'non-uk-passport' page response
    When I submit a 'next' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit an '<device-type>' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context '<device-type>-appOnly'
    When the async DCMAW CRI produces a 'kenneth-changed-family-name-driving-permit-valid' VC
    And I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
    When I submit a 'next' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context '<device-type>-appOnly'

    Examples:
      | device-type |
      | iphone      |
      | android     |
