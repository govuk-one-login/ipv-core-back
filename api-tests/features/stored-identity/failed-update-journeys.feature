@Build @QualityGateIntegrationTest
Feature: Failed update details
  Background: Create user with existing credentials and SI record
    Given I activate the 'storedIdentityService,disableStrategicApp' feature set
    And the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |

  Rule: Reuse journey
    Background: Start reuse journey with update details
      # Use non-expired fraud credentials
      And the subject already has the following credentials
        | CRI   | scenario        |
        | fraud | kenneth-score-1 |
      And I have an existing stored identity record with a 'P1' vot

      # Start reuse journey
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit an 'update-details' event
      Then I get a 'update-details' page response

    Scenario: Reuse journey - failed address change - failed COI (valid identity)
      When I submit a 'address-only' event
      Then I get a 'address' CRI response
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'invalid'
      When I submit 'kenneth-changed' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'alice-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityValid'
      When I submit an 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'valid'

    Scenario: Reuse journey - failed name change - fail with CI (invalid identity)
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      # SI record invalidated as part of reset-session-identity lambda
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'invalid'
      When I submit 'kenneth-passport-with-breaching-ci' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'invalid'

    Scenario: Reuse journey - failed name change - fail with no ci (valid identity)
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      # SI record invalidated as part of reset-session-identity lambda
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'invalid'
      When I submit 'kenneth-passport-verification-zero' details to the CRI stub
      Then I get an 'update-details-failed' page response
      When I submit a 'continue' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'valid'

    Scenario: Reuse journey - failed name change - user abandons journey
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      # SI record invalidated as part of reset-session-identity lambda
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'invalid'
      When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
      Then I get an 'page-dcmaw-success' page response with context 'coiNoAddress'

      # User stops here and abandons journey
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'invalid'

  Rule: Repeat fraud check
    Background: Start repeat fraud check journey
      And the subject already has the following expired credentials
        | CRI   | scenario        |
        | fraud | kenneth-score-1 |
      And I have an existing stored identity record with a 'P1' vot

      # Start repeat fraud check journey with update name
      When I start a new 'low-confidence' journey
      Then I get a 'confirm-your-details' page response
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'invalid'

    Scenario: RFC - failed address change - failed COI (invalid identity)
      When I submit a 'address-only' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'alice-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get an 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'invalid'

    Scenario: RFC - failed update name - fail with CI (invalid identity)
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-with-breaching-ci' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'invalid'

    Scenario: RFC - failed update name - fail with no CI (invalid identity)
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-verification-zero' details to the CRI stub
      Then I get an 'update-details-failed' page response with context 'existingIdentityInvalid'
      When I submit a 'return-to-service' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'invalid'

    Scenario: RFC - failed update name - user abandons journey
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
      Then I get an 'page-dcmaw-success' page response with context 'coiNoAddress'

      # User stops here and abandons journey
      And I have a GPG45 stored identity record type with a 'P1' vot that is 'invalid'
