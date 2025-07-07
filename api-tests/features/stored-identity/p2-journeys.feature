@Build
Feature: Stored Identity - P2 journeys
  Background: Enabled stored identity service flag and start p1 journey
    Given I activate the 'storedIdentityService,disableStrategicApp' feature sets
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response

  Scenario: Successful stored identity storage - P2 app international journey
    And I submit an 'international' event
    Then I get a 'non-uk-app-intro' page response
    When I submit a 'useApp' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-changed' details with attributes to the CRI stub
      | Attribute | Values               |
      | context   | "international_user" |
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-no-applicable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And I have a 'GPG45' stored identity record type with a 'P2' vot

  Rule: Non-international journeys
    Background: start non-international journey
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response

    Scenario: Successful stored identity storage - P2 web journey
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'page-multiple-doc-check' page response
      When I submit a 'ukPassport' event
      Then I get a 'ukPassport' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'kbv' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And I have a 'GPG45' stored identity record type with a 'P2' vot

    Scenario: Successful stored identity storage - P2 app journey that meets P3
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-1' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And I have a 'GPG45' stored identity record type with a 'P3' vot

    Scenario: Successful stored identity storage - P2 F2F journey
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit a 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'f2f' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the async CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'page-face-to-face-handoff' page response

        # Return journey
      When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And I have a 'GPG45' stored identity record type with a 'P2' vot

    Scenario: Successful stored identity storage - P2 no photo ID journey
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I activate the 'storedIdentityService' feature set
      And I submit 'kenneth-current' details with attributes to the CRI stub
        | Attribute | Values         |
        | context   | "bank_account" |
      Then I get a 'bav' CRI response
      When I submit 'kenneth' details to the CRI stub
      Then I get a 'nino' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'kbv' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And I have a 'GPG45' stored identity record type with a 'P2' vot

  Scenario: Reuse journey - identity is stored to EVCS - identity meets P3
    Given the subject already has the following credentials
      | CRI     | scenario               |
      | dcmaw   | kenneth-passport-valid |
      | address | kenneth-current        |
      | fraud   | kenneth-score-2        |
    And I don't have a stored identity in EVCS

    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And I have a 'GPG45' stored identity record type with a 'P3' vot

  Scenario: Reuse journey - identity is stored to EVCS - identity only meets P2
    Given the subject already has the following credentials
      | CRI        | scenario               |
      | ukPassport | kenneth-passport-valid |
      | address    | kenneth-current        |
      | fraud      | kenneth-score-2        |
      | kbv        | kenneth-score-2        |
    And I don't have a stored identity in EVCS

    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And I have a 'GPG45' stored identity record type with a 'P2' vot
