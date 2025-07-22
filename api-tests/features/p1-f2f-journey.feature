@Build
Feature: P1 F2F journey
  Background: Disable the strategic app
    Given I activate the 'disableStrategicApp' feature set

  Scenario: P1 Face to Face after DCMAW dropout
    Given I activate the 'p1Journeys' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response with context 'nino'
    When I submit an 'end' event
    Then I get a 'pyi-post-office' page response
    When I submit a 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
    Then I get a 'page-face-to-face-handoff' page response

  Scenario: P1 F2F Support low strength F2F documents for thin fraud file users
    Given I activate the 'p1Journeys' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response with context 'nino'
    When I submit an 'end' event
    Then I get a 'pyi-post-office' page response
    When I submit a 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1-history-0' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-passport-valid' details with attributes to the CRI stub
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
    Then I get a 'page-face-to-face-handoff' page response

  Rule: F2F journey after no NI
    Background: Route to F2F
      Given I activate the 'p1Journeys' feature set
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit a 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-1' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'f2f' CRI response

    Scenario: P1 F2F Journey - pending
      When I submit 'kenneth-passport-valid' details with attributes to the CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      Given I start a new 'low-confidence' journey
      Then I get a 'page-ipv-pending' page response

    Scenario: P1 F2F Journey - successful
      When I submit 'kenneth-passport-valid' details with attributes to the async CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new 'low-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
