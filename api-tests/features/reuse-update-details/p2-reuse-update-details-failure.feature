@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Identity reuse update details failures
    Rule: Update given name only
        Background:
            Given the subject already has the following credentials
                | CRI     | scenario               |
                | dcmaw   | kenneth-passport-valid |
                | address | kenneth-current        |
                | fraud   | kenneth-score-2        |
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response
            When I submit an 'update-details' event
            Then I get an 'update-details' page response
            When I submit a 'given-names-only' event
            Then I get a 'page-update-name' page response

        Scenario: DCMAW access denied OAuth error
            When I submit an 'update-name' event
            Then I get an 'identify-device' page response
            When I submit an 'appTriage' event
            Then I get a 'pyi-triage-select-device' page response
            When I submit a 'smartphone' event
            Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
            When I submit an 'iphone' event
            Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
            When the async DCMAW CRI produces an 'access_denied' error response
            And I pass on the DCMAW callback
            Then I get a 'check-mobile-app-result' page response
            When I poll for async DCMAW credential receipt
            Then the poll returns a '201'
            When I submit the returned journey event
            Then I get an 'update-details-failed' page response
            When I submit a 'continue' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response

        Scenario: Decide not to use app - fails update, but keeps old identity
            When I submit a 'update-name' event
            Then I get an 'identify-device' page response
            When I submit an 'appTriage' event
            Then I get a 'pyi-triage-select-device' page response
            When I submit a 'smartphone' event
            Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
            When I submit an 'iphone' event
            Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
            When I submit an 'anotherWay' event
            Then I get an 'update-details-failed' page response
            When I submit a 'continue' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity

        Scenario: User is able to delete account from update-details-failed page
            When I submit an 'update-name' event
            Then I get an 'identify-device' page response
            When I submit an 'appTriage' event
            Then I get a 'pyi-triage-select-device' page response
            When I submit a 'computer-or-tablet' event
            Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
            When I submit a 'neither' event
            Then I get a 'pyi-triage-buffer' page response
            When I submit an 'anotherWay' event
            Then I get an 'update-details-failed' page response
            When I submit a 'delete' event
            Then I get a 'delete-handover' page response

        Scenario: fail-with-no-ci from DCMAW
            When I submit an 'update-name' event
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
            Then I get an 'update-details-failed' page response
            When I submit a 'continue' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response

        # TODO: uncomment and update this to use the strategic app once PYIC-8769/8941/8940 have been resolved
#        Scenario: Breaching CI received from DCMAW - doesn't receive old identity
#            When I activate the 'disableStrategicApp' feature set
#            And I submit an 'update-name' event
#            Then I get a 'dcmaw' CRI response
#            When I submit 'kenneth-driving-permit-breaching-ci' details to the CRI stub
#            Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
#            When I submit a 'returnToRp' event
#            Then I get an OAuth response
#            When I use the OAuth response to get my identity
#            Then I get a 'P0' identity
#            When I start a new 'medium-confidence' journey
#            Then I get a 'pyi-no-match' page response

        # TODO: uncomment and update this to use the strategic app once PYIC-8769/8941 have been resolved
#        Scenario: Breaching CI from DL auth source check - doesn't receive old identity
#            When I activate the 'disableStrategicApp' feature set
#            When I submit a 'update-name' event
#            Then I get a 'dcmaw' CRI response
#            When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
#            Then I get a 'drivingLicence' CRI response
#            When I submit 'kenneth-driving-permit-needs-alternate-doc' details with attributes to the CRI stub
#                | Attribute | Values          |
#                | context   | "check_details" |
#            Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
#            When I submit a 'returnToRp' event
#            Then I get an OAuth response
#            When I use the OAuth response to get my identity
#            Then I get a 'P0' identity
#            When I start a new 'medium-confidence' journey
#            Then I get a 'pyi-driving-licence-no-match' page response

        Scenario: User is able to delete account from sorry-could-not-confirm-details page - MAM
            And I submit an 'update-name' event
            Then I get an 'identify-device' page response
            When I submit an 'appTriage' event
            Then I get a 'pyi-triage-select-device' page response
            When I submit a 'smartphone' event
            Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
            When I submit an 'android' event
            Then I get a 'pyi-triage-mobile-download-app' page response with context 'android-appOnly'
            When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC with a CI
            # And the user returns from the app to core-front
            And I pass on the DCMAW callback
            Then I get a 'check-mobile-app-result' page response
            When I poll for async DCMAW credential receipt
            Then the poll returns a '201'
            When I submit the returned journey event
            Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
            When I submit a 'delete' event
            Then I get a 'delete-handover' page response

        Scenario: User is able to delete account from sorry-could-not-confirm-details page - DAD
            And I submit an 'update-name' event
            Then I get an 'identify-device' page response
            When I submit an 'appTriage' event
            Then I get a 'pyi-triage-select-device' page response
            When I submit a 'computer-or-tablet' event
            Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
            When I submit an 'iphone' event
            Then I get a 'pyi-triage-desktop-download-app' page response with context 'iphone-appOnly'
            When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC with a CI
            And I poll for async DCMAW credential receipt
            Then the poll returns a '201'
            When I submit the returned journey event
            Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
            When I submit a 'delete' event
            Then I get a 'delete-handover' page response

        Scenario: Zero score in fraud CRI - receives old identity (P2)
            When I submit an 'update-name' event
            Then I get an 'identify-device' page response
            When I submit an 'appTriage' event
            Then I get a 'pyi-triage-select-device' page response
            When I submit a 'computer-or-tablet' event
            Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
            When I submit an 'android' event
            Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly'
            When the async DCMAW CRI produces a 'kennethD' 'drivingPermit' 'success' VC
            And I poll for async DCMAW credential receipt
            Then the poll returns a '201'
            When I submit the returned journey event
            Then I get a 'drivingLicence' CRI response
            When I submit 'kenneth-changed-given-name-driving-permit-valid' details with attributes to the CRI stub
                | Attribute | Values          |
                | context   | "check_details" |
            Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I submit 'kenneth-changed-given-name-score-0' details with attributes to the CRI stub
                | Attribute          | Values                   |
                | evidence_requested | {"identityFraudScore":2} |
            Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityValid'
            When I submit a 'returnToRp' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response

        Scenario: Breaching CI received from fraud CRI - doesn't receive old identity
            When I submit an 'update-name' event
            Then I get an 'identify-device' page response
            When I submit an 'appTriage' event
            Then I get a 'pyi-triage-select-device' page response
            When I submit a 'computer-or-tablet' event
            Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
            When I submit an 'android' event
            Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly'
            When the async DCMAW CRI produces a 'kennethD' 'drivingPermit' 'success' VC
            And I poll for async DCMAW credential receipt
            Then the poll returns a '201'
            When I submit the returned journey event
            Then I get a 'drivingLicence' CRI response
            When I submit 'kenneth-changed-given-name-driving-permit-valid' details with attributes to the CRI stub
                | Attribute | Values          |
                | context   | "check_details" |
            Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I submit 'kenneth-breaching-ci' details with attributes to the CRI stub
                | Attribute          | Values                   |
                | evidence_requested | {"identityFraudScore":2} |
            Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
            When I submit a 'returnToRp' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P0' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'pyi-no-match' page response

        Scenario: Breaching CI received from TICF CRI
            Given TICF CRI will respond with default parameters and
                | cis | BREACHING |
            When I submit an 'update-name' event
            Then I get an 'identify-device' page response
            When I submit an 'appTriage' event
            Then I get a 'pyi-triage-select-device' page response
            When I submit a 'computer-or-tablet' event
            Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
            When I submit an 'android' event
            Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly'
            When the async DCMAW CRI produces a 'kenneth-changed-given-name-passport-valid' VC
            And I poll for async DCMAW credential receipt
            Then the poll returns a '201'
            When I submit the returned journey event
            Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I submit 'kenneth-changed-given-name-score-2' details with attributes to the CRI stub
                | Attribute          | Values                   |
                | evidence_requested | {"identityFraudScore":1} |
            Then I get a 'pyi-no-match' page response
            When I submit a 'next' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P0' identity
            And the TICF VC has properties
                | cis  | BREACHING      |
                | type | RiskAssessment |

        Scenario: Failed COI check - receives old identity (P2)
            When I submit an 'update-name' event
            Then I get an 'identify-device' page response
            When I submit an 'appTriage' event
            Then I get a 'pyi-triage-select-device' page response
            When I submit a 'computer-or-tablet' event
            Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
            When I submit an 'android' event
            Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly'
            When the async DCMAW CRI produces a 'alice-passport-valid' VC
            And I poll for async DCMAW credential receipt
            Then the poll returns a '201'
            When I submit the returned journey event
            Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I submit 'alice-score-2' details with attributes to the CRI stub
                | Attribute          | Values                   |
                | evidence_requested | {"identityFraudScore":1} |
            Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityValid'
            When I submit an 'returnToRp' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response

        Scenario: Fraud access denied OAuth error - receives old identity (P2)
            When I submit an 'update-name' event
            Then I get an 'identify-device' page response
            When I submit an 'appTriage' event
            Then I get a 'pyi-triage-select-device' page response
            When I submit a 'computer-or-tablet' event
            Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
            When I submit an 'android' event
            Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly'
            When the async DCMAW CRI produces a 'kenneth-changed-given-name-driving-permit-valid' VC
            And I poll for async DCMAW credential receipt
            Then the poll returns a '201'
            When I submit the returned journey event
            Then I get a 'drivingLicence' CRI response
            When I submit 'kenneth-changed-given-name-driving-permit-valid' details with attributes to the CRI stub
                | Attribute | Values          |
                | context   | "check_details" |
            Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I call the CRI stub with attributes and get an 'access_denied' OAuth error
                | Attribute          | Values                   |
                | evidence_requested | {"identityFraudScore":2} |
            Then I get an 'sorry-could-not-confirm-details' page response with context 'existingIdentityValid'
            When I submit a 'returnToRp' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response

    Rule: Update address only
        Background:
            Given the subject already has the following credentials
                | CRI     | scenario               |
                | dcmaw   | kenneth-passport-valid |
                | address | kenneth-current        |
                | fraud   | kenneth-score-2        |
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response
            When I submit an 'update-details' event
            Then I get an 'update-details' page response
            When I submit a 'address-only' event
            Then I get an 'address' CRI response

        Scenario: Address access denied OAuth error - receives old identity (P2) when continuing to service
            When I call the CRI stub with attributes and get an 'access_denied' OAuth error
                | Attribute | Values               |
                | context   | "international_user" |
            Then I get an 'sorry-could-not-confirm-details' page response with context 'existingIdentityValid'
            When I submit a 'returnToRp' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity
