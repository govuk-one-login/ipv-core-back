@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Reprove Identity Journey

  Scenario: Happy path user reproves identity on desktop android
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
    When I start a new 'medium-confidence' journey
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'prove-identity-again-app' page response
    When I submit a 'useApp' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit an 'android' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly'
    When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
    And I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When The AIS stub will return an 'AIS_NO_INTERVENTION' result
    And I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: Happy path user reproves identity on mobile iphone
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
    When I start a new 'medium-confidence' journey
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'prove-identity-again-app' page response
    When I submit an 'useApp' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit a 'end' event
    Then I get a 'need-id-prove-identity-again-app' page response
    When I submit a 'useApp' event
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
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When The AIS stub will return an 'AIS_NO_INTERVENTION' result
    And I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: User doesn't have photo ID, returns to RP
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
    When I start a new 'medium-confidence' journey
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'prove-identity-again-app' page response
    When I submit an 'useApp' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit a 'end' event
    Then I get a 'need-id-prove-identity-again-app' page response
    When I submit an 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

  Scenario: User doesn't have photo ID, deletes account
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
    When I start a new 'medium-confidence' journey
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'prove-identity-again-app' page response
    When I submit an 'useApp' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit a 'end' event
    Then I get a 'need-id-prove-identity-again-app' page response
    When I submit an 'delete' event
    Then I get a 'delete-handover' page response with context 'reproveIdentity'

  Scenario: User doesn't have a smartphone, deletes account
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
    When I start a new 'medium-confidence' journey
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'prove-identity-again-app' page response
    When I submit a 'useApp' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit a 'neither' event
    Then I get a 'need-prove-identity-again-no-app' page response
    When I submit an 'delete' event
    Then I get a 'delete-handover' page response with context 'reproveIdentity'

  Scenario: Desktop user fails to prove identity and returns to RP
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
    When I start a new 'medium-confidence' journey
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'prove-identity-again-app' page response
    When I submit a 'useApp' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit an 'android' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly'
    When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC
    And I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'sorry-could-not-confirm-identity-reprove-failure' page response
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

  Scenario: Desktop user fails to prove identity with a CI and returns to RP
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
    When I start a new 'medium-confidence' journey
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'prove-identity-again-app' page response
    When I submit a 'useApp' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit an 'android' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly'
    When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC with a CI
    And I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'sorry-could-not-confirm-identity-reprove-failure' page response
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

  Scenario: Mobile user fails to prove identity and returns to RP
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
    When I start a new 'medium-confidence' journey
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'prove-identity-again-app' page response
    When I submit an 'useApp' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit a 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
    When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'sorry-could-not-confirm-identity-reprove-failure' page response
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

  Scenario: Mobile user fails to prove identity with a CI and returns to RP
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
    When I start a new 'medium-confidence' journey
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'prove-identity-again-app' page response
    When I submit an 'useApp' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit a 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
    When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC with a CI
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'sorry-could-not-confirm-identity-reprove-failure' page response
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

  Rule: Authoritative source check fails
    Background:
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
      When I start a new 'medium-confidence' journey
      Then I get a 'reprove-identity-start' page response
      When I submit a 'next' event
      Then I get a 'prove-identity-again-app' page response
      When I submit an 'useApp' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit a 'end' event
      Then I get a 'need-id-prove-identity-again-app' page response
      When I submit a 'useApp' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
      When the async DCMAW CRI produces a 'kennethD' 'drivingPermit' 'success' VC
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'drivingLicence' CRI response
      # Driving licence auth source check fails
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'uk-driving-licence-details-not-correct-reprove' page response

    Scenario: User reproves identity after driving licence auth check fail
      When I submit a 'next' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
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
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When The AIS stub will return an 'AIS_NO_INTERVENTION' result
      And I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: User deletes account after driving licence auth check fail
      When I submit an 'end' event
      Then I get a 'need-prove-identity-again-app' page response
      When I submit an 'delete' event
      Then I get a 'delete-handover' page response with context 'reproveIdentity'