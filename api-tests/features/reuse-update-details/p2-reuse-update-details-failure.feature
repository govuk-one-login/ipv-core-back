@Build
Feature: Identity reuse update details failures

    Rule: Update given name only

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
            When I submit a 'given-names-only' event
            Then I get a 'page-update-name' page response
            When I submit an 'update-name' event
            Then I get a 'dcmaw' CRI response

        @FastFollow
        Scenario: Given name change - DCMAW access denied OAuth error
            Given I activate the 'updateDetailsAccountDeletion' feature set
            When I get an 'access_denied' OAuth error from the CRI stub
            Then I get an 'update-details-failed' page response
            When I submit a 'continue' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response

        @FastFollow
        Scenario: Given name change - fail-with-no-ci from DCMAW
            Given I activate the 'updateDetailsAccountDeletion' feature set
            When I submit 'kenneth-passport-verification-zero' details to the CRI stub
            Then I get an 'update-details-failed' page response
            When I submit a 'continue' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response

        Scenario: Given name change - breaching CI received from DCMAW
            When I submit 'kenneth-driving-permit-breaching-ci' details to the CRI stub
            Then I get a 'sorry-could-not-confirm-details' page response
            When I submit a 'end' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P0' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'pyi-no-match' page response

        Scenario: Given name change - zero score in fraud CRI
            When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
            Then I get a 'page-dcmaw-success' page response
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I submit 'kenneth-changed-given-name-score-0' details to the CRI stub
            Then I get a 'sorry-could-not-confirm-details' page response
            When I submit a 'end' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P0' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response

        Scenario: Given name change - breaching CI received from fraud CRI
            When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
            Then I get a 'page-dcmaw-success' page response
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I submit 'kenneth-breaching-ci' details to the CRI stub
            Then I get a 'sorry-could-not-confirm-details' page response
            When I submit a 'end' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P0' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'pyi-no-match' page response

        Scenario: Given name change - breaching CI received from TICF CRI
            When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
            Then I get a 'page-dcmaw-success' page response
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I submit 'kenneth-changed-given-name-score-2' details to the CRI stub
            Then I get a 'page-ipv-success' page response
            When I submit a 'next' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity
            Given TICF CRI will respond with default parameters and
                | cis | BREACHING |
            When I start a new 'medium-confidence' journey
            Then I get a 'pyi-no-match' page response
            When I submit a 'next' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P0' identity
            And the TICF VC has properties
                | cis  | BREACHING      |
                | type | RiskAssessment |

        Scenario: Given name change - failed COI check
            When I submit 'alice-passport-valid' details to the CRI stub
            Then I get a 'page-dcmaw-success' page response
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I submit 'alice-score-2' details to the CRI stub
            Then I get a 'sorry-could-not-confirm-details' page response
            When I submit an 'end' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P0' identity

        Scenario: Given name change - Fraud access denied OAuth error
            When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
            Then I get a 'page-dcmaw-success' page response
            When I submit a 'next' event
            Then I get a 'fraud' CRI response
            When I get an 'access_denied' OAuth error from the CRI stub
            Then I get an 'sorry-could-not-confirm-details' page response
            When I submit a 'end' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P0' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response

    Rule: Update address only

        Scenario: Given name change - Address access denied OAuth error
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
            When I get an 'access_denied' OAuth error from the CRI stub
            Then I get an 'sorry-could-not-confirm-details' page response
            When I submit a 'end' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P0' identity
            When I start a new 'medium-confidence' journey
            Then I get a 'page-ipv-reuse' page response
