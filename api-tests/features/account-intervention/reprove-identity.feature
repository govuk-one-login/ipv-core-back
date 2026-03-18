@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Reprove Identity Journey

  Rule: Flag from AIS use state comparison
    Scenario Outline: User reproves identity with AIS (<intervention>)
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      And The AIS stub will return an '<ais_response>' result
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
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit an 'android' event
      Then I get a 'pyi-triage-desktop-download-app' page response with context 'android'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
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
      And I have a GPG45 stored identity record type with a 'P3' vot

      Examples:
        | intervention                        | ais_response                        |
        | Reverify                            | AIS_FORCED_USER_IDENTITY_VERIFY     |
        | Password reset cleared and reverify | PASSWORD_RESET_CLEARED_AND_REVERIFY |

    Scenario: User reproves with F2F with AIS
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
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit a 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'f2f' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the async CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'page-face-to-face-handoff' page response

        # Return journey after popping out to the Post Office
      When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And I have a GPG45 stored identity record type with a 'P2' vot

    Scenario: User needs to reprove their identity with F2F pending with AIS
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit a 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'f2f' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the async CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'page-face-to-face-handoff' page response

        # Users been to the Post Office but sadly now has an account intervention
      Given The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
      And I start a new 'medium-confidence' journey
      Then I get a 'reprove-identity-start' page response
      When I submit a 'next' event
      Then I get a 'live-in-uk' page response

  Rule: F2F journeys are subject to COI checks
    Background:
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
      When I start a new 'medium-confidence' journey with reprove identity
      Then I get a 'reprove-identity-start' page response
      When I submit a 'next' event
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit a 'next' event
      Then I get a 'claimedIdentity' CRI response

    Scenario: Reproving with F2F journey with same identity passes COI check
      When I submit 'kenneth-current' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'f2f' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the async CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'page-face-to-face-handoff' page response

            # Return journey after popping out to the Post Office
      When I start new 'medium-confidence' journeys with reprove identity until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And I have a GPG45 stored identity record type with a 'P2' vot

    Scenario: Reproving with F2F journey with different identity fails COI check
      When I submit 'lora' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'lora-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'lora-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And I don't have a stored identity in EVCS

  Rule: App only reprove journey
    Background:
      Given I activate the 'reproveViaAppOnly' feature set

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
      And I have a GPG45 stored identity record type with a 'P3' vot

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
      And I have a GPG45 stored identity record type with a 'P3' vot

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
      And I don't have a stored identity in EVCS

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
      And I don't have a stored identity in EVCS

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
      And I don't have a stored identity in EVCS

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
      And I don't have a stored identity in EVCS

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
      And I don't have a stored identity in EVCS

  Rule: App only reprove journey authoritative source check fails
    Background:
      Given I activate the 'reproveViaAppOnly' feature set
      And the subject already has the following credentials
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

    Scenario: User reproves identity after driving licence auth check fail
      # Driving licence auth source check fails
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'uk-driving-licence-details-not-correct-reprove' page response
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
      And I have a GPG45 stored identity record type with a 'P2' vot

    Scenario: User deletes account after driving licence auth check fail
      # Driving licence auth source check fails
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'uk-driving-licence-details-not-correct-reprove' page response
      When I submit an 'end' event
      Then I get a 'need-prove-identity-again-app' page response
      When I submit an 'delete' event
      Then I get a 'delete-handover' page response with context 'reproveIdentity'

    Scenario: User retries after CI from authoritative source check and is denied due to CI.
      # Driving licence auth source check fails with a CI
      When I submit 'kenneth-driving-permit-needs-alternate-doc' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'sorry-could-not-confirm-identity-reprove-failure' page response
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      # Return to try again
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
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And I don't have a stored identity in EVCS
