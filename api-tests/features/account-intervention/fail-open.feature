@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Fail open scenarios
  Rule: Compare AIS descriptions
    Background: Enable AIS description checking
      Given I activate the 'disableAisStateCheck' feature set

    Scenario Outline: Journey with AIS failures but no interventions succeeds
      Given The AIS stub will return an '<first_ais_response>' result
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
      When the async DCMAW CRI produces a 'kenneth-passport-valid' VC
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
      When The AIS stub will return an '<second_ais_response>' result
      And I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response

      Examples:
        | first_ais_response  | second_ais_response |
        | ERROR               | AIS_NO_INTERVENTION |
        | AIS_NO_INTERVENTION | ERROR               |
        | ERROR               | ERROR               |

    Scenario Outline: Journey with AIS failure and <intervention> intervention fails
      Given The AIS stub will return an '<first_ais_response>' result
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
      When the async DCMAW CRI produces a 'kenneth-passport-valid' VC
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
      When The AIS stub will return an '<second_ais_response>' result
      And I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get an OAuth response with error code 'session_invalidated'
      And I don't have a stored identity in EVCS

      Examples:
        | intervention           | first_ais_response  | second_ais_response             |
        | final blocked          | ERROR               | AIS_ACCOUNT_BLOCKED             |
        | final reprove identity | ERROR               | AIS_FORCED_USER_IDENTITY_VERIFY |

    Scenario: Reprove identity journey with AIS failure succeeds
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
      When I start a new 'medium-confidence' journey
      Then I get a 'reprove-identity-start' page response
      When I submit a 'next' event
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
      When the async DCMAW CRI produces a 'kenneth-passport-valid' VC
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
      When The AIS stub will return an 'ERROR' result
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response

  Rule: Compare AIS states
    Background: Enable AIS state checking
      Given I activate the 'aisStateCheck' feature set

    Scenario Outline: Journey with AIS failures but no interventions succeeds
      Given The AIS stub will return an '<first_ais_response>' result
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
      When the async DCMAW CRI produces a 'kenneth-passport-valid' VC
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
      When The AIS stub will return an '<second_ais_response>' result
      And I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response

      Examples:
        | first_ais_response  | second_ais_response |
        | ERROR               | AIS_NO_INTERVENTION |
        | AIS_NO_INTERVENTION | ERROR               |
        | ERROR               | ERROR               |

    Scenario Outline: Journey with AIS failure and <intervention> intervention fails
      Given The AIS stub will return an '<first_ais_response>' result
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
      When the async DCMAW CRI produces a 'kenneth-passport-valid' VC
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
      When The AIS stub will return an '<second_ais_response>' result
      And I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get an OAuth response with error code 'session_invalidated'
      And I don't have a stored identity in EVCS

      Examples:
        | intervention           | first_ais_response  | second_ais_response             |
        | final blocked          | ERROR               | AIS_ACCOUNT_BLOCKED             |
        | final reprove identity | ERROR               | AIS_FORCED_USER_IDENTITY_VERIFY |

    Scenario: Reprove identity journey with AIS failure succeeds
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
      When I start a new 'medium-confidence' journey
      Then I get a 'reprove-identity-start' page response
      When I submit a 'next' event
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
      When the async DCMAW CRI produces a 'kenneth-passport-valid' VC
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
      When The AIS stub will return an 'ERROR' result
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response
