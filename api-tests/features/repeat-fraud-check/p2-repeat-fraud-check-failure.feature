@Build @QualityGateIntegrationTest
Feature: Repeat fraud check failures
  Background: Disable the strategic app
    Given I activate the 'disableStrategicApp' feature set

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
      Then I get a 'dcmaw' CRI response

    Scenario: DCMAW access denied OAuth error
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get an 'update-details-failed' page response with context 'existingIdentityInvalid'
      When I submit a 'return-to-service' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

    Scenario: Applicable authoritative source failed check evidence too weak
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-no-applicable' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

    Scenario: Applicable authoritative source failed check evidence too weak
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-unavailable' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

    Scenario: User is able to delete account from update-details-failed screen
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get an 'update-details-failed' page response with context 'existingIdentityInvalid'
      When I submit a 'delete' event
      Then I get a 'delete-handover' page response

    Scenario: Breaching CI received from DCMAW
      When I submit 'kenneth-driving-permit-breaching-ci' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'pyi-no-match' page response

    Scenario: User is able to delete account from sorry-could-not-confirm-details screen
      When I submit 'kenneth-driving-permit-breaching-ci' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'delete' event
      Then I get a 'delete-handover' page response

    Scenario: Zero score in fraud CRI
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
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
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

    Scenario: Breaching CI received from fraud CRI
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
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

    Scenario: Failed COI check
      When I submit 'alice-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'alice-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
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

    Scenario: Fraud access denied OAuth error
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
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
      When I call the CRI stub with attributes and get an 'access_denied' OAuth error
            | Attribute | Values               |
            | context   | "international_user" |
      Then I get an 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response
