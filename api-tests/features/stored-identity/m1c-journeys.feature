@Build
Feature: Stored Identity - M1C Outcomes
  Background:
    Given I activate the 'storedIdentityService' feature set

  Rule: New Identities - UK Address
    Background:
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response

    Scenario: Successful M1C P2 identity via DCMAW using chipped passport
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-unavailable' details to the CRI stub
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And I have a 'GPG45' stored identity record type with a 'P2' vot

    Scenario: Successful M1C P2 identity via DCMAW using chipped BRP
      When I submit 'kenneth-brp-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-unavailable' details to the CRI stub
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And I have a 'GPG45' stored identity record type with a 'P2' vot

    Scenario: No stored identity - unsuccessful M1C journey
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'page-multiple-doc-check' page response
      When I submit a 'drivingLicence' event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-unavailable' details to the CRI stub
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And I don't have a stored identity in EVCS

  Rule: New Identities - International Address
    Background:
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'international' event
      Then I get a 'non-uk-app-intro' page response
      When I submit a 'useApp' event
      Then I get a 'dcmaw' CRI response

    Scenario: Successful M1C P2 identity via DCMAW using chipped passport
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-changed' details with attributes to the CRI stub
        | Attribute | Values               |
        | context   | "international_user" |
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-unavailable' details to the CRI stub
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And I have a 'GPG45' stored identity record type with a 'P2' vot

  Rule: Returning existing M1C user goes through details confirmation
    Background:
      Given the subject already has the following credentials
        | CRI        | scenario               |
        | dcmawAsync | kenneth-passport-valid |
        | address    | kenneth-current        |
        | fraud      | kenneth-unavailable    |
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

    Scenario Outline: Existing M1C address and name change - <selected-name-change>
      When I submit a '<selected-name-change>' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit '<details>' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
      When I submit a 'next' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit '<fraud-details>' details to the CRI stub
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And my identity 'GivenName' is '<expected-given-name>'
      And my identity 'FamilyName' is '<expected-family-name>'
      And I have a 'GPG45' stored identity record type with a 'P2' vot

      Examples:
        | selected-name-change    | details                                    | fraud-details                           | expected-given-name | expected-family-name |
        | family-name-and-address | kenneth-changed-family-name-passport-valid | kenneth-changed-family-name-unavailable | Kenneth             | Smith                |
        | given-names-and-address | kenneth-changed-given-name-passport-valid  | kenneth-changed-given-name-unavailable  | Ken                 | Decerqueira          |
