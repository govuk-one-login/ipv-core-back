@Build
Feature: P1 No Photo Id Journey

  Scenario: P1 No Photo Id Journey
    Given I start a new 'low-confidence' journey with feature set 'p1Journeys'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
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
    And an 'IPV_IDENTITY_ISSUED' audit event was recorded [local only]

  Scenario: P1 No Photo Id after DCMAW dropout Journey
    Given I start a new 'low-confidence' journey with feature set 'p1Journeys'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-multiple-doc-check' page response with context 'nino'
    When I submit a 'nino' event
    Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
    When I submit a 'next' event
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
    When I submit 'kenneth-score-1' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                    |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity
    And an 'IPV_IDENTITY_ISSUED' audit event was recorded [local only]

  Scenario: P1 No Photo Id Journey - NINO dropout
    Given I start a new 'low-confidence' journey with feature set 'p1Journeys,dwpKbvTest'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
    When I submit an 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details with attributes to the CRI stub
      | Attribute | Values         |
      | context   | "hmrc_check"   |
    Then I get a 'nino' CRI response
    When I call the CRI stub with attributes and get an 'access_denied' OAuth error
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
    Then I get a 'no-photo-id-abandon-find-another-way' page response

  Scenario: P1 No Photo Id Journey - DWP KBV
    Given I start a new 'low-confidence' journey with feature set 'p1Journeys,dwpKbvTest'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
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
    Then I get a 'personal-independence-payment' page response
    When I submit a 'next' event
    Then I get a 'page-pre-dwp-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'dwpKbv' CRI response
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity

  Scenario: P1 No Photo Id Journey - DWP KBV PIP page dropout
    Given I start a new 'low-confidence' journey with feature set 'p1Journeys,dwpKbvTest'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
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
    Then I get a 'personal-independence-payment' page response
    When I submit a 'end' event
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

  Scenario: P1 No Photo Id Journey - DWP KBV transition page dropout
    Given I start a new 'low-confidence' journey with feature set 'p1Journeys,dwpKbvTest'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
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
    Then I get a 'personal-independence-payment' page response
    When I submit a 'next' event
    Then I get a 'page-pre-dwp-kbv-transition' page response
    When I submit a 'end' event
    Then I get a 'no-photo-id-security-questions-find-another-way' page response with context 'dropout'
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity

  Scenario: P1 No Photo Id Journey - HMRC KBV
    Given I start a new 'low-confidence' journey with feature set 'p1Journeys,m2bBetaHmrcKbv'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
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
    Then I get a 'hmrcKbv' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity

  Scenario: P1 No Photo Id Journey user drops out of HMRC KBV CRI via thin file or failed checks - HMRC KBV
    Given I start a new 'low-confidence' journey with feature set 'p1Journeys,m2bBetaHmrcKbv'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
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
    Then I get a 'hmrcKbv' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity

  Scenario: P1 No suitable ID
    Given I start a new 'low-confidence' journey with feature set 'p1Journeys'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
    When I submit an 'end' event
    Then I get a 'page-ipv-identity-postoffice-start' page response with context 'lastChoice'
    When I submit a 'end' event
    Then I get a 'pyi-escape' page response
