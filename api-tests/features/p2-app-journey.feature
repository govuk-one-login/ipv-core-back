@Build @QualityGateIntegrationTest @QualityGateRegressionTest
@TrafficGeneration
Feature: P2 App journey

  Scenario Outline: MAM Successful <attained-vot> identity via DCMAW using <doc> - <journey-type>
    When I start a new '<journey-type>' journey
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
    When the async DCMAW CRI produces a '<details>' VC
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
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a '<attained-vot>' identity

    Examples:
      | journey-type           | doc             | details                       | attained-vot |
      | high-medium-confidence | passport        | kenneth-passport-valid        | P3           |
      | high-medium-confidence | BRC             | kenneth-brc-valid             | P2           |
      | high-medium-confidence | BRP             | kenneth-brp-valid             | P3           |
      | medium-confidence      | passport        | kenneth-passport-valid        | P2           |
      | medium-confidence      | BRC             | kenneth-brc-valid             | P2           |
      | medium-confidence      | BRP             | kenneth-brp-valid             | P2           |

  Scenario Outline: MAM Failed DCMAW with CI should result in P0 - <journey-type>
    When I start a new '<journey-type>' journey
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
    When the async DCMAW CRI produces a 'kenneth-driving-permit-with-breaching-ci' VC
      # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

    Examples:
      | journey-type           |
      | high-medium-confidence |
      | medium-confidence      |

  Rule: Medium confidence journeys
    Background: Start journey
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get an 'identify-device' page response

    Scenario: Multiple callbacks do not incorrectly progress the journey
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      # Repeat callback
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response

    Scenario: Polling returns 404 until CRI received
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      # And the user returns from the app to core-front
      When I pass on the DCMAW callback
      Then I get an 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '404'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'

    Scenario: MAM journey detected iphone
      When I submit an 'mobileDownloadIphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'

    Scenario: MAM journey detected iphone - invalid OS version
      When I submit an 'appTriageSmartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'

    Scenario: MAM journey declared android
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'android' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'android'

    Scenario: MAM journey detected android
      When I submit an 'mobileDownloadAndroid' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'android'

    Scenario: MAM Fail DCMAW with no CI - route to alternative IPV method
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kenneth-passport-fail-no-ci' VC
        # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-multiple-doc-check' page response

    Scenario: MAM journey abandoned without a VC
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces an 'access_denied' error response
      # This will probably need to change once the polling is working
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-multiple-doc-check' page response

    Scenario: MAM journey cross-browser scenario unsuccessful VC without CI
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kenneth-passport-fail-no-ci' VC
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-multiple-doc-check' page response

    Scenario: MAM journey no compatible smartphone
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit a 'neither' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit an 'neither' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-multiple-doc-check' page response

    Scenario: MAM journey cross-browser scenario unsuccessful VC with CI
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC with a CI
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

    Scenario Outline: Happy path DAD journey - <device>
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
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | device  |
        | iphone  |
        | android |

    Scenario: DAD journey iphone fails with ci and goes to no match page
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-desktop-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC with a CI
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get an 'pyi-no-match' page response

    Scenario: DAD journey credential fails with with no ci and continues to other methods
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-desktop-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get an 'page-multiple-doc-check' page response

    Scenario: DAD journey no compatible smartphone
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit a 'neither' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-multiple-doc-check' page response

    Scenario: Strategic app uk address user wants to go back over identify-device page
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'back' event
      Then I get a 'page-ipv-identity-document-start' page response

    Scenario Outline: <error> from DCMAW
      When I start a new 'medium-confidence' journey
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
      When the async DCMAW CRI produces an '<error>' error response
      When I wait for 1 seconds for the async credential to be processed
      # This will probably need to change once the polling is working
      And I pass on the DCMAW callback
      Then I get a 'pyi-technical' page response

      Examples:
        | error                     |
        | server_error              |
        | temporarily_unavailable   |
        | invalid_request           |
        | unauthorized_client       |
        | unsupported_response_type |
        | invalid_scope             |
