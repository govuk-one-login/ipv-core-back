@Build
Feature: Repeat fraud check failures

  Rule: Given name change only

    Background:
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
      And the subject already has the following expired credentials
        | CRI   | scenario        |
        | fraud | kenneth-score-2 |
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
      When I submit an 'update-name' event
      Then I get a 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response

    @FastFollow
    Scenario: DCMAW access denied OAuth error
      Given I activate the 'updateDetailsAccountDeletion' feature set
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get an 'update-details-failed' page response with context 'existingIdentityInvalid'
      When I submit a 'return-to-service' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

    @FastFollow
    Scenario: User is able to delete account from update-details-failed screen
      Given I activate the 'updateDetailsAccountDeletion' feature set
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get an 'update-details-failed' page response with context 'existingIdentityInvalid'
      When I submit a 'delete' event
      Then I get a 'delete-handover' page response

    Scenario: Breaching CI received from DCMAW
      When I submit 'kenneth-driving-permit-breaching-ci' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response
      When I submit a 'end' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'pyi-no-match' page response

    @FastFollow
    Scenario: Breaching CI received from DCMAW
      Given I activate the 'updateDetailsAccountDeletion' feature set
      When I submit 'kenneth-driving-permit-breaching-ci' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'pyi-no-match' page response

    @FastFollow
    Scenario: User is able to delete account from sorry-could-not-confirm-details screen
      Given I activate the 'updateDetailsAccountDeletion' feature set
      When I submit 'kenneth-driving-permit-breaching-ci' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'delete' event
      Then I get a 'delete-handover' page response

    Scenario: Zero score in fraud CRI
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-given-name-score-0' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response
      When I submit a 'end' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

    @FastFollow
    Scenario: Zero score in fraud CRI
      Given I activate the 'updateDetailsAccountDeletion' feature set
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-given-name-score-0' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

    Scenario: Breaching CI received from fraud CRI
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
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

    @FastFollow
    Scenario: Breaching CI received from fraud CRI
      Given I activate the 'updateDetailsAccountDeletion' feature set
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
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

    Scenario: Failed COI check
      When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-family-name-score-2' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response

    @FastFollow
    Scenario: Failed COI check
      Given I activate the 'updateDetailsAccountDeletion' feature set
      When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-family-name-score-2' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

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

    Scenario: Fraud access denied OAuth error
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get an 'sorry-could-not-confirm-details' page response
      When I submit a 'end' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

    @FastFollow
    Scenario: Fraud access denied OAuth error
      Given I activate the 'updateDetailsAccountDeletion' feature set
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get an 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

  Rule: Update address only
    Background:
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
      And the subject already has the following expired credentials
        | CRI   | scenario        |
        | fraud | kenneth-score-2 |
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response
      When I submit a 'address-only' event
      Then I get an 'address' CRI response

    Scenario: Address access denied OAuth error
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get an 'sorry-could-not-confirm-details' page response
      When I submit a 'end' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

    @FastFollow
    Scenario: Address access denied OAuth error
      Given I activate the 'updateDetailsAccountDeletion' feature set
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get an 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response
