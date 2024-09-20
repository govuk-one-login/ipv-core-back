@Build
Feature: P1 No Photo Id Journey

  Scenario: P1 No Photo Id Journey
    Given I start a new 'low-confidence' journey with feature set 'p1Journeys'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response
    When I submit an 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details with attributes to the CRI stub
      | Attribute | Values         |
      | context   | "hmrc_check"   |
    Then I get a 'nino' CRI response
    When I submit 'kenneth' details with attributes to the CRI stub
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity
