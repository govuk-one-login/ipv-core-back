@Build
Feature: M1C Unavailable Journeys
  Background: Disable the strategic app
    Given I activate the 'disableStrategicApp' feature set

  Rule: New identities
    Background:
      Given I start a new 'medium-confidence' journey
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

    Scenario: Unsuccessful M1C P2 identity via web DL using DL
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

  Rule: Returning existing M1C unavailable user goes through details confirmation
    Background:
      Given the subject already has the following credentials
        | CRI           | scenario                     |
        | dcmawAsync    | kenneth-passport-valid       |
        | address       | kenneth-current              |
        | fraud         | kenneth-unavailable          |
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

    Scenario Outline: No details changed, finish with <endScore>
      # Repeat fraud check with no update
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit <fraudResponse> details to the CRI stub
      Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | fraudResponse            | endScore  |
        | 'kenneth-unavailable'    | 'M1C'     |
        | 'kenneth-score-2'        | 'M1A'     |

    Scenario Outline: Existing M1C name change, finish with <endScore>
      When I submit a 'family-name-only' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-family-name-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit <fraudResponse> details to the CRI stub
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | fraudResponse                                | endScore  |
        | 'kenneth-changed-family-name-unavailable'    | 'M1C'     |
        | 'kenneth-changed-family-name-score-2'        | 'M1A'     |

    Scenario Outline: Existing M1C address change, finish with  <endScore>
      When I submit an 'address-only' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit <fraudResponse> details to the CRI stub
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | fraudResponse            | endScore  |
        | 'kenneth-unavailable'    | 'M1C'     |
        | 'kenneth-score-2'        | 'M1A'     |

    Scenario Outline: Existing M1C address and name change, finish with  <endScore>
      # Repeat fraud check with update address and family name
      When I submit a 'family-name-and-address' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-family-name-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
      When I submit a 'next' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit <fraudResponse> details to the CRI stub
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | fraudResponse                                | endScore  |
        | 'kenneth-changed-family-name-unavailable'    | 'M1C'     |
        | 'kenneth-changed-family-name-score-2'        | 'M1A'     |

    Scenario: Existing M1C name change to M1A using DL
      When I submit a 'family-name-only' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-changed-family-name-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-family-name-score-2' details to the CRI stub
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

  Rule: Existing non-M1C identity returns
    Background:
      Given the subject already has the following credentials
        | CRI           | scenario                     |
        | dcmawAsync    | kenneth-passport-valid       |
        | address       | kenneth-current              |
        | fraud         | kenneth-score-2              |
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit a 'update-details' event
      Then I get a 'update-details' page response

    Scenario: Existing M1A user can change name with unavailable fraud check
      When I submit a 'family-name-only' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-family-name-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-family-name-unavailable' details to the CRI stub
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: Existing M1A user cannot change name with DL and unavailable fraud check
      When I submit a 'family-name-only' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-changed-family-name-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-family-name-unavailable' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityValid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
