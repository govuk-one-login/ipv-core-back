@Build
Feature: P2 reuse journeys
  Background: Enable feature sets
    Given I activate the 'storedIdentityService,disableStrategicApp' feature sets

  Rule: Existing credentials that meet P3
      Background: Create user with existing credentials
        And the subject already has the following credentials
          | CRI     | scenario               |
          | dcmaw   | kenneth-passport-valid |
          | address | kenneth-current        |
          | fraud   | kenneth-score-2        |

      Scenario: Reuse journey - identity is stored to EVCS - no existing SI - identity meets P3
        And I don't have a stored identity in EVCS

        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I get a 'P2' identity
        And I have a 'GPG45' stored identity record type with a 'P3' vot

      Scenario: Reuse journey - identity is stored to EVCS - no existing SI - identity only meets P2
        And I don't have a stored identity in EVCS

        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I get a 'P2' identity
        And I have a 'GPG45' stored identity record type with a 'P3' vot

      Scenario: Medium-confidence reuse journey with update - SI record stored to EVCS - existing SI
        And I have an existing stored identity record with a 'P3' vot

        # New reuse p2 journey with update name
        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit an 'update-details' event
        Then I get a 'update-details' page response
        When I submit a 'given-names-only' event
        Then I get a 'page-update-name' page response
        When I submit a 'update-name' event
        Then I get a 'dcmaw' CRI response
        # SI record invalidated as part of reset-session-identity lambda
        And I have a 'GPG45' stored identity record type with a 'P3' vot that is 'invalid'

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
        Then I get a 'P2' identity
        And I have a 'GPG45' stored identity record type with a 'P3' vot that is 'valid'

      Scenario: High-medium confidence journey - previous P3 identity downgraded to P2 when updating with DL details
        And I don't have a stored identity in EVCS

        # Reuse journey with no update
        When I start a new 'high-medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I get a 'P3' identity
        And I have a 'GPG45' stored identity record type with a 'P3' vot

        # Reuse journey with update
        When I start a new 'high-medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit an 'update-details' event
        Then I get a 'update-details' page response
        When I submit a 'given-names-only' event
        Then I get a 'page-update-name' page response
        When I submit a 'update-name' event
        Then I get a 'dcmaw' CRI response
        # SI record invalidated as part of reset-session-identity lambda
        And I have a 'GPG45' stored identity record type with a 'P3' vot that is 'invalid'
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
        Then I get a 'P2' identity
        And I have a 'GPG45' stored identity record type with a 'P2' vot

    Rule: Existing identity that meets P2
      Background: User has existing identity that meets P2 identity
        Given the subject already has the following credentials
          | CRI     | scenario                     |
          | dcmaw   | kenneth-driving-permit-valid |
          | address | kenneth-current              |
          | fraud   | kenneth-score-2              |
        And I have an existing stored identity record with a 'P2' vot

      Scenario: Reuse journey with initial P2 vot - update with passport results in P3
        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit an 'update-details' event
        Then I get a 'update-details' page response
        When I submit a 'given-names-only' event
        Then I get a 'page-update-name' page response
        When I submit a 'update-name' event
        Then I get a 'dcmaw' CRI response
        # SI record invalidated as part of reset-session-identity lambda
        And I have a 'GPG45' stored identity record type with a 'P2' vot that is 'invalid'
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
        Then I get a 'P2' identity
        And I have a 'GPG45' stored identity record type with a 'P3' vot
