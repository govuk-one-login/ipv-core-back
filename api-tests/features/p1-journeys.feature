@Build
Feature: P1 journey

  Scenario: P1 App Journey
    Given I activate the 'p1Journeys' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity
    And an 'IPV_IDENTITY_ISSUED' audit event was recorded [local only]

  Scenario: P1 Passport after DCMAW dropout
    Given I activate the 'p1Journeys' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response with context 'nino'
    When I submit an 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details to the CRI stub
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

  Scenario: P1 Driving Licence after DCMAW dropout
    Given I activate the 'p1Journeys' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response with context 'nino'
    When I submit an 'drivingLicence' event
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details to the CRI stub
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
    When I submit 'kenneth-score-1' details to the CRI stub
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
    Then I get a 'page-face-to-face-handoff' page response

  Scenario: P1 Passport after multiple dropouts
    Given I activate the 'p1Journeys' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response with context 'nino'
    When I submit an 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'prove-identity-another-type-photo-id' page response with context 'passport'
    When I submit an 'otherPhotoId' event
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'prove-identity-another-type-photo-id' page response with context 'drivingLicence'
    When I submit an 'otherPhotoId' event
    Then I get a 'ukPassport' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details to the CRI stub
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

  Scenario: P1 DCMAW after KBV dropout Journey
    Given I activate the 'p1Journeys' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
    When I submit a 'next' event
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
    When I submit 'kenneth-score-1' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-0' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
    Then I get a 'no-photo-id-security-questions-find-another-way' page response with context 'dropout'
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity
    And an 'IPV_IDENTITY_ISSUED' audit event was recorded [local only]

  Scenario: P1 F2F Journey
    Given I activate the 'p1Journeys' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
    When I submit an 'end' event
    Then I get a 'page-ipv-identity-postoffice-start' page response with context 'lastChoice'
    When I submit a 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details to the CRI stub
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-passport-valid' details with attributes to the CRI stub
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
    When I submit 'kenneth-score-1-history-0' details to the CRI stub
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-passport-valid' details with attributes to the CRI stub
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
    Then I get a 'page-face-to-face-handoff' page response

  Scenario: P1 Validate the Evidence requested for low confidence journey in Experian KBV
    Given I activate the 'p1Journeys' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response with context 'nino'
    When I submit an 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details to the CRI stub
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

  Scenario: P1 Validate the Evidence requested for low confidence journey in DWP KBV
    Given I activate the 'p1Journeys,dwpKbvTest' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response with context 'nino'
    When I submit an 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details to the CRI stub
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

  Scenario: P1 Validate the Evidence requested for low confidence journey in HMRC KBV
    Given I activate the 'p1Journeys,m2bBetaHmrcKbv' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response with context 'nino'
    When I submit an 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details to the CRI stub
    Then I get a 'nino' CRI response
    When I submit 'kenneth-score-1' details to the CRI stub
    Then I get a 'hmrcKbv' CRI response
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity
