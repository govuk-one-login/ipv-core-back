@Build @InitialisesDCMAWSessionState @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: P1 app journey
  Background: Start journey
    Given I activate the 'strategicApp' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response

  Scenario Outline: MAM successful app journey - <device>
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an '<device>' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context '<device>'
    When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
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
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity

    Examples:
      | device  |
      | iphone  |
      | android |

  Scenario: MAM journey credential fails with no ci and continues to other methods
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
    When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC
      # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get an 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get an 'page-multiple-doc-check' page response with context 'nino'

  Scenario: MAM journey credential fails with ci and goes to no match page
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
    When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC with a CI
      # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get an 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get an 'pyi-no-match' page response

  Scenario: MAM journey no compatible smartphone continues to other methods
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit a 'neither' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit an 'neither' event
    Then I get a 'pyi-triage-buffer' page response
    When I submit an 'anotherWay' event
    Then I get a 'page-multiple-doc-check' page response with context 'nino'

  Scenario: MAM journey detected iphone
    When I submit an 'mobileDownloadIphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'

  Scenario: MAM journey detected iphone - invalid OS version
    When I submit an 'appTriageSmartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'

  Scenario: MAM journey detected android
    When I submit an 'mobileDownloadAndroid' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'android'

  Scenario Outline: : DAD successful app journey
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit an '<device>' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context '<device>'
    When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
    And I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity

    Examples:
      | device  |
      | iphone  |
      | android |

  Scenario: DAD journey no compatible smartphone continues to other methods
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit a 'neither' event
    Then I get a 'pyi-triage-buffer' page response
    When I submit an 'anotherWay' event
    Then I get a 'page-multiple-doc-check' page response with context 'nino'
