@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: P2 International Address
  Rule: Medium-confidence journeys

    Background:
      And I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response

    Scenario: User resides in the UK and navigates to the start page
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response

    Scenario: International address user is taken back to smartphone triage after selecting neither initially then trying again
      When I submit a 'international' event
      Then I get a 'non-uk-passport' page response
      When I submit a 'next' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit a 'neither' event
      Then I get a 'non-uk-no-app-options' page response
      When I submit a 'useApp' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'

    Scenario: International address user decides to return to RP from DCMAW exit page
      When I submit a 'international' event
      Then I get a 'non-uk-passport' page response
      When I submit a 'next' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit a 'neither' event
      Then I get a 'non-uk-no-app-options' page response
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity

    Scenario: Successful P2 international identity via DCMAW using passport
      When I submit an 'international' event
      Then I get a 'non-uk-passport' page response
      When I submit a 'next' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
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
      When I submit 'kenneth-changed' details with attributes to the CRI stub
        | Attribute | Values               |
        | context   | "international_user" |
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-no-applicable' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity with a fraud VC

    Scenario: User looks for alternative methods to prove identity without using the app
      When I submit an 'international' event
      Then I get a 'non-uk-passport' page response
      When I submit an 'abandon' event
      Then I get a 'non-uk-no-passport' page response
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

    Scenario: International user abandons due to no biometric passport then returns
      When I submit an 'international' event
      Then I get a 'non-uk-passport' page response
      When I submit a 'abandon' event
      Then I get a 'non-uk-no-passport' page response
      When I submit a 'useApp' event
      Then I get an 'identify-device' page response

    Scenario: International user wants to prove identity another way from download page
      When I submit an 'international' event
      Then I get a 'non-uk-passport' page response
      When I submit a 'next' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit a 'iphone' event
      Then I get a 'pyi-triage-desktop-download-app' page response with context 'iphone-appOnly'
      When I submit a 'preferNoApp' event
      Then I get a 'non-uk-no-app-options' page response
      # Change their mind and go back
      When I submit a 'useApp' event
      Then I get a 'pyi-triage-desktop-download-app' page response with context 'iphone-appOnly'
      # Decide to abandon again
      When I submit a 'preferNoApp' event
      Then I get a 'non-uk-no-app-options' page response
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

  Rule: High-medium confidence journeys
    Background: Start high-medium confidence journey
      And I start a new 'high-medium-confidence' journey
      Then I get a 'live-in-uk' page response

    Scenario: Successful P2 received via DCMAW
      When I submit an 'international' event
      Then I get a 'non-uk-passport' page response
      When I submit a 'next' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
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
      When I submit 'kenneth-changed' details with attributes to the CRI stub
        | Attribute | Values               |
        | context   | "international_user" |
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-no-applicable' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
