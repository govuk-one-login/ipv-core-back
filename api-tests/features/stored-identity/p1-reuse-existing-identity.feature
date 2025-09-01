@Build
Feature: Stored Identity - Update Existing Identity
  Background: Enable feature sets
    Given I activate the 'storedIdentityService,disableStrategicApp' feature set

  Rule: Non-update journey - no existing SI record
    Background: Existing user identity - start low-confidence journey
      And the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      And I don't have a stored identity in EVCS
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-reuse' page response

    Scenario: Reuse journey with no update
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And I have a GPG45 stored identity record type with a 'P2' vot

  Rule: Update journeys - no existing SI record
    Background: Existing identity - continue to update details
      And the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |

      And I don't have a stored identity in EVCS
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit a 'update-details' event
      Then I get a 'update-details' page response

    Scenario: Address Update
      When I submit a 'address-only' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And I have a GPG45 stored identity record type with a 'P2' vot

    Scenario Outline: Successful Name Change - <selected-name-change> - meets P2
      When I submit a '<selected-name-change>' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit '<details>' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit '<details>' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit '<fraud-details>' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And my identity 'GivenName' is '<expected-given-name>'
      And my identity 'FamilyName' is '<expected-family-name>'
      And I have a GPG45 stored identity record type with a 'P2' vot

      Examples:
        | selected-name-change | details                                          | fraud-details                       | expected-given-name | expected-family-name |
        | family-name-only     | kenneth-changed-family-name-driving-permit-valid | kenneth-changed-family-name-score-2 | Kenneth             | Smith                |
        | given-names-only     | kenneth-changed-given-name-driving-permit-valid  | kenneth-changed-given-name-score-2  | Ken                 | Decerqueira          |

    Scenario Outline: Successful Name Change - <selected-name-change> - meets P3
      When I submit a '<selected-name-change>' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit '<details>' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit '<fraud-details>' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And my identity 'GivenName' is '<expected-given-name>'
      And my identity 'FamilyName' is '<expected-family-name>'
      And I have a GPG45 stored identity record type with a 'P3' vot

      Examples:
        | selected-name-change | details                                    | fraud-details                       | expected-given-name | expected-family-name |
        | family-name-only     | kenneth-changed-family-name-passport-valid | kenneth-changed-family-name-score-2 | Kenneth             | Smith                |
        | given-names-only     | kenneth-changed-given-name-passport-valid  | kenneth-changed-given-name-score-2  | Ken                 | Decerqueira          |

  Rule: Update journey - existing SI record
    Scenario: Existing P2 identity - reuse P1 journey with update
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      And I have an existing stored identity record with a 'P2' vot

      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit an 'update-details' event
      Then I get a 'update-details' page response
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      # SI record invalidated as part of reset-session-identity lambda
      And I have a GPG45 stored identity record type with a 'P2' vot that is 'invalid'

      When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-given-name-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And I have a GPG45 stored identity record type with a 'P3' vot that is 'valid'

    Scenario: Existing P1 credentials - details used for update meet P2
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-1              |
      And I have an existing stored identity record with a 'P1' vot

      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit an 'update-details' event
      Then I get a 'update-details' page response
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      # SI record invalidated as part of reset-session-identity lambda
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'invalid'

      When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-given-name-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And I have a GPG45 stored identity record type with a 'P2' vot that is 'valid'
