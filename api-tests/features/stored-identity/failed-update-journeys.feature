Feature: Failed update details
  Background: Start new P1 journey
    Given I activate the 'p1Journeys,storedIdentityService,disableStrategicApp' feature sets
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response

  Rule: Reuse journey
    Background: Start reuse journey with name update
      # Use non-expired fraud credentials
      When I submit 'kenneth-score-1' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And I have a 'GPG45' stored identity record type with a 'P1' vot

      # Start reuse journey
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit an 'update-details' event
      Then I get a 'update-details' page response
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
        # SI record invalidated as part of reset-session-identity lambda
      And I have a 'GPG45' stored identity record type with a 'P1' vot that is 'invalid'

    Scenario: Reuse journey - failed name change - fail with CI (invalid identity)
      When I submit 'kenneth-passport-with-breaching-ci' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And I have a 'GPG45' stored identity record type with a 'P1' vot that is 'invalid'

    Scenario: Reuse journey - failed name change - fail with no ci (valid identity)
      When I submit 'kenneth-passport-verification-zero' details to the CRI stub
      Then I get an 'update-details-failed' page response
      When I submit a 'continue' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And I have a 'GPG45' stored identity record type with a 'P1' vot that is 'valid'

    Scenario: Reuse journey - failed name change - user abandons journey
      When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
      Then I get an 'page-dcmaw-success' page response with context 'coiNoAddress'

      # User stops here and abandons journey
      And I have a 'GPG45' stored identity record type with a 'P1' vot that is 'invalid'

  Rule: Repeat fraud check
    Background: Start repeat fraud check journey
      # Use expired fraud credentials
      When I submit expired 'kenneth-score-1' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And I have a 'GPG45' stored identity record type with a 'P1' vot

      # Start repeat fraud check journey with update name
      When I start a new 'low-confidence' journey
      Then I get a 'confirm-your-details' page response
      And I have a 'GPG45' stored identity record type with a 'P1' vot that is 'invalid'
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response

    Scenario: RFC - failed update name - fail with CI (invalid identity)
      When I submit 'kenneth-passport-with-breaching-ci' details to the CRI stub
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And I have a 'GPG45' stored identity record type with a 'P1' vot that is 'invalid'

    Scenario: RFC - failed update name - fail with no CI (invalid identity)
      When I submit 'kenneth-passport-verification-zero' details to the CRI stub
      Then I get an 'update-details-failed' page response with context 'existingIdentityInvalid'
      When I submit a 'return-to-service' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And I have a 'GPG45' stored identity record type with a 'P1' vot that is 'invalid'

    Scenario: RFC - failed update name - user abandons journey
      When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
      Then I get an 'page-dcmaw-success' page response with context 'coiNoAddress'

      # User stops here and abandons journey
      And I have a 'GPG45' stored identity record type with a 'P1' vot that is 'invalid'
