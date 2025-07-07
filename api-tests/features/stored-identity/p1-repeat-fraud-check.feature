@Build
Feature: Stored Identity - repeat fraud check
  Background:
    Given I activate the 'storedIdentityService,disableStrategicApp' feature set
    And the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
    And the subject already has the following expired credentials
      | CRI   | scenario        |
      | fraud | kenneth-score-2 |
    When I start a new 'low-confidence' journey
    Then I get a 'confirm-your-details' page response

  Scenario: Fraud 6 Months Expiry + No Update
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity
    And I have a 'GPG45' stored identity record type with a 'P2' vot

  Scenario Outline: Fraud 6 Months Expiry + Address and Name Change - <selected-name-change> - meets P2
    When I submit a '<selected-name-change>' event
    Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
    When I submit a 'update-name' event
    Then I get a 'dcmaw' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I submit '<details>' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
    When I submit a 'next' event
    Then I get a 'address' CRI response
    When I submit 'kenneth-changed' details with attributes to the CRI stub
      | Attribute | Values               |
      | context   | "international_user" |
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
    And I have a 'GPG45' stored identity record type with a 'P2' vot

    Examples:
      | selected-name-change    | details                                          | fraud-details                       | expected-given-name | expected-family-name |
      | family-name-and-address | kenneth-changed-family-name-driving-permit-valid | kenneth-changed-family-name-score-2 | Kenneth             | Smith                |
      | given-names-and-address | kenneth-changed-given-name-driving-permit-valid  | kenneth-changed-given-name-score-2  | Ken                 | Decerqueira          |

  Scenario Outline: Fraud 6 Months Expiry + Address and Name Change - <selected-name-change> - meets P3
    When I submit a '<selected-name-change>' event
    Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
    When I submit a 'update-name' event
    Then I get a 'dcmaw' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
    When I submit a 'next' event
    Then I get a 'address' CRI response
    When I submit 'kenneth-changed' details with attributes to the CRI stub
      | Attribute | Values               |
      | context   | "international_user" |
    Then I get a 'fraud' CRI response
    When I submit '<fraud-details>' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'updateIdentity'
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity
    And I have a 'GPG45' stored identity record type with a 'P3' vot

    Examples:
      | selected-name-change    | details                                    | fraud-details                       | expected-given-name | expected-family-name |
      | family-name-and-address | kenneth-changed-family-name-passport-valid | kenneth-changed-family-name-score-2 | Kenneth             | Smith                |
      | given-names-and-address | kenneth-changed-given-name-passport-valid  | kenneth-changed-given-name-score-2  | Ken                 | Decerqueira          |
