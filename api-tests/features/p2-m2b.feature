@Build
Feature: M2B No Photo Id Journey

  Scenario: M2B Journey
    Given I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'page-ipv-identity-postoffice-start' page response
    When I submit an 'end' event with feature set 'm2bBetaExperianKbv'
    Then I get a 'prove-identity-no-photo-id' page response
    When I submit an 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details to the CRI stub and see requested attributes
      | Attribute | Values         |
      | context   | "bank_account" |
    Then I get a 'bav' CRI response
    When I submit 'kenneth' details to the CRI stub
    Then I get a 'nino' CRI response
    When I submit 'kenneth' details to the CRI stub and see requested attributes
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
