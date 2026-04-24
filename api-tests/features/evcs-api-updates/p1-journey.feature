@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: P1 EvcsUpdates Journeys
  Scenario: P1 No Photo Id Journey
    Given I activate the 'evcsApiUpdates' feature set
    And I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response and pageContext
      | Context  | Value |
      | ninoOnly | true  |
    When I submit an 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details with attributes to the CRI stub
      | Attribute | Values         |
      | context   | "hmrc_check"   |
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
    Then I get a 'personal-independence-payment' page response
    When I submit a 'end' event
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'experianKbv' CRI response
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I am issued a 'P1' identity
    And I have a stored identity record with a 'P1' max vot

  Scenario: P1 Face to Face after DCMAW dropout
    Given I activate the 'evcsApiUpdates' feature set
    And I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response and pageContext
      | Context    | Value |
      | deviceType | dad   |
    When I submit a 'neither' event
    Then I get a 'pyi-triage-buffer' page response
    When I submit an 'anotherWay' event
    Then I get a 'page-multiple-doc-check' page response and pageContext
      | Context   | Value |
      | allowNino | true  |
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

  Rule: CIMIT
    Background:
      Given I activate the 'evcsApiUpdates' feature set
      And I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | dad   |
      When I submit a 'neither' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-multiple-doc-check' page response and pageContext
        | Context   | Value |
        | allowNino | true  |

    Scenario Outline: Alternate doc mitigation via passport or DL
      When I submit an '<initialCri>' event
      Then I get a '<initialCri>' CRI response
      When I submit '<initialInvalidDoc>' details to the CRI stub
      Then I get a '<noMatchPage>' page response
      When I submit a 'next' event
      Then I get a '<mitigatingCri>' CRI response
      When I submit '<mitigatingDoc>' details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-score-1' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P1' identity
      And I have a stored identity record with a 'P1' max vot

      Examples:
        | initialCri        | initialInvalidDoc                          | noMatchPage                              | mitigatingCri  | mitigatingDoc                |
        | drivingLicence    | kenneth-driving-permit-needs-alternate-doc | pyi-driving-licence-no-match-another-way | ukPassport     | kenneth-passport-valid       |
        | ukPassport        | kenneth-passport-needs-alternate-doc       | pyi-passport-no-match-another-way        | drivingLicence | kenneth-driving-permit-valid |
