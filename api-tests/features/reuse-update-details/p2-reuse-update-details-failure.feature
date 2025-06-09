@Build
Feature: Identity reuse update details failures

    Rule: Update given name only

        Background:
            Given the subject already has the following credentials
                | CRI     | scenario                     |
                | dcmaw   | kenneth-driving-permit-valid |
                | address | kenneth-current              |
                | fraud   | kenneth-score-2              |
            And I activate the 'disableStrategicApp' feature set
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response
            When I submit an 'update-details' event
            Then I get an 'update-details' page response
            When I submit a 'given-names-only' event
            Then I get a 'page-update-name' page response
            When I submit an 'update-name' event
            Then I get a 'dcmaw' CRI response

        Scenario: DCMAW access denied OAuth error
            When I call the CRI stub and get an 'access_denied' OAuth error
            Then I get an 'update-details-failed' page response
            When I submit a 'continue' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response

        Scenario: User is able to delete account from update-details-failed page
            When I call the CRI stub and get an 'access_denied' OAuth error
            Then I get an 'update-details-failed' page response
            When I submit a 'delete' event
            Then I get a 'delete-handover' page response

        Scenario: fail-with-no-ci from DCMAW
            When I submit 'kenneth-passport-verification-zero' details to the CRI stub
            Then I get an 'update-details-failed' page response
            When I submit a 'continue' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response

        Scenario: Breaching CI received from DCMAW - doesn't receive old identity
            When I submit 'kenneth-driving-permit-breaching-ci' details to the CRI stub
            Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
            When I submit a 'returnToRp' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P0' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'pyi-no-match' page response

        Scenario: User is able to delete account from sorry-could-not-confirm-details page
            When I submit 'kenneth-driving-permit-breaching-ci' details to the CRI stub
            Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
            When I submit a 'delete' event
            Then I get a 'delete-handover' page response

        Scenario: Zero score in fraud CRI - receives old identity (P2)
            When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
            Then I get a 'drivingLicence' CRI response
            When I submit 'kenneth-changed-given-name-driving-permit-valid' details with attributes to the CRI stub
                | Attribute | Values          |
                | context   | "check_details" |
            Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I submit 'kenneth-changed-given-name-score-0' details to the CRI stub
            Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityValid'
            When I submit a 'returnToRp' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response

        Scenario: Breaching CI received from fraud CRI - doesn't receive old identity
            When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
            Then I get a 'drivingLicence' CRI response
            When I submit 'kenneth-changed-given-name-driving-permit-valid' details with attributes to the CRI stub
                | Attribute | Values          |
                | context   | "check_details" |
            Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I submit 'kenneth-breaching-ci' details to the CRI stub
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
            When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
            Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I submit 'kenneth-changed-given-name-score-2' details to the CRI stub
            Then I get a 'pyi-no-match' page response
            When I submit a 'next' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P0' identity
            And the TICF VC has properties
                | cis  | BREACHING      |
                | type | RiskAssessment |

        Scenario: Failed COI check - receives old identity (P2)
            When I submit 'alice-passport-valid' details to the CRI stub
            Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I submit 'alice-score-2' details to the CRI stub
            Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityValid'
            When I submit an 'returnToRp' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response

        Scenario: Fraud access denied OAuth error - receives old identity (P2)
            When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
            Then I get a 'drivingLicence' CRI response
            When I submit 'kenneth-changed-given-name-driving-permit-valid' details with attributes to the CRI stub
                | Attribute | Values          |
                | context   | "check_details" |
            Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I call the CRI stub and get an 'access_denied' OAuth error
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
                | CRI     | scenario                     |
                | dcmaw   | kenneth-driving-permit-valid |
                | address | kenneth-current              |
                | fraud   | kenneth-score-2              |
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
