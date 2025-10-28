@Build
Feature: P2 no photo id journey
  Rule: Experian KBV
    Background: Start P2 no photo id with Experian KBV
      Given I activate the 'm2bBetaExperianKbv' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'next' event
      Then I get a 'claimedIdentity' CRI response

    Scenario: P2 no photo id journey - Experian - Happy path
      When I submit 'kenneth-current' details with attributes to the CRI stub
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
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: P2 no photo id journey - Experian - BAV dropout:
      When I submit 'kenneth-current' details with attributes to the CRI stub
        | Attribute | Values         |
        | context   | "bank_account" |
      Then I get a 'bav' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'no-photo-id-abandon-find-another-way' page response

    Scenario: P2 no photo id journey - Experian - Breaching BAV CI
      When I submit 'kenneth-current' details with attributes to the CRI stub
        | Attribute | Values         |
        | context   | "bank_account" |
      Then I get a 'bav' CRI response
      When I submit 'kenneth-with-breaching-ci' details to the CRI stub
      Then I get a 'pyi-no-match' page response with context 'bankAccount'

    Scenario: P2 no photo id journey - Experian - NINO dropout:
      When I submit 'kenneth-current' details with attributes to the CRI stub
        | Attribute | Values         |
        | context   | "bank_account" |
      Then I get a 'bav' CRI response
      When I submit 'kenneth' details to the CRI stub
      Then I get a 'nino' CRI response
      When I call the CRI stub with attributes and get an 'access_denied' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get a 'no-photo-id-abandon-find-another-way' page response

    Scenario: P2 no photo id journey - Experian - Breaching NINO CI
      When I submit 'kenneth-current' details with attributes to the CRI stub
        | Attribute | Values         |
        | context   | "bank_account" |
      Then I get a 'bav' CRI response
      When I submit 'kenneth' details to the CRI stub
      Then I get a 'nino' CRI response
      When I submit 'kenneth-with-breaching-ci' details with attributes to the CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get a 'pyi-no-match' page response with context 'nino'

    Scenario: P2 no photo id journey - Experian - Drops out via thin file or failed checks
      When I submit 'kenneth-current' details with attributes to the CRI stub
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
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-score-0' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'no-photo-id-security-questions-find-another-way' page response with context 'dropout'

    Scenario: P2 no photo id journey - Experian - Breaching KBV CI
      When I submit 'kenneth-current' details with attributes to the CRI stub
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
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-with-breaching-ci' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'pyi-no-match' page response

    Scenario: P2 no photo id journey - Experian - KBV CI mitigation:
      When I submit 'kenneth-current' details with attributes to the CRI stub
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
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-needs-enhanced-verification' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'no-photo-id-security-questions-find-another-way' page response

    Scenario: P2 no photo id journey - Experian - Breaching BAV CI
      When I submit 'kenneth-current' details with attributes to the CRI stub
        | Attribute | Values         |
        | context   | "bank_account" |
      Then I get a 'bav' CRI response
      When I submit 'kenneth-with-breaching-ci' details to the CRI stub
      Then I get a 'pyi-no-match' page response with context 'bankAccount'

  Rule: Abandon
    Background: Abandon P2 no photo id journey
      Given I activate the 'm2bBetaExperianKbv' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details with attributes to the CRI stub
        | Attribute | Values         |
        | context   | "bank_account" |
      Then I get a 'bav' CRI response
      When I submit 'kenneth' details to the CRI stub
      Then I get a 'nino' CRI response
      When I call the CRI stub with attributes and get an 'access_denied' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get a 'no-photo-id-abandon-find-another-way' page response

    Scenario: P2 no photo id journey - Abandon - DCMAW
      Given I activate the 'disableStrategicApp' feature set
      When I submit an 'mobileApp' event
      Then I get a 'dcmaw' CRI response

    Scenario: P2 no photo id journey - Abandon - Strategic app
      Given I activate the 'strategicApp' feature set
      When I submit an 'mobileApp' event
      Then I get a 'identify-device' page response

    Scenario: P2 no photo id journey - Abandon - Passport
      When I submit an 'passport' event
      Then I get a 'ukPassport' CRI response

    Scenario: P2 no photo id journey - Abandon - Driving licence
      When I submit an 'drivingLicence' event
      Then I get a 'drivingLicence' CRI response

    Scenario: P2 no photo id journey - Abandon - F2F
      When I submit an 'postOffice' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'f2f' CRI response

    Scenario: P2 no photo id journey - Abandon - Return to RP
      When I submit an 'relyingParty' event
      Then I get an OAuth response

  Rule: Escape
    Background: Escape P2 no photo id journey
      Given I activate the 'm2bBetaExperianKbv' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'end' event
      Then I get a 'no-photo-id-exit-find-another-way' page response

    Scenario: P2 no photo id journey - Escape - Use photo id
      When I submit an 'next' event
      Then I get a 'page-ipv-identity-document-start' page response

    Scenario: P2 no photo id journey - Escape - Return to no photo id
      When I submit an 'bankAccount' event
      Then I get a 'prove-identity-no-photo-id' page response

    Scenario: P2 no photo id journey - Escape - Return to RP
      When I submit an 'end' event
      Then I get an OAuth response

  Rule: KBV mitigation
    Background: Start P2 no photo id KBV mitigation journey
      Given I activate the 'm2bBetaExperianKbv' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details with attributes to the CRI stub
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
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-needs-enhanced-verification' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'no-photo-id-security-questions-find-another-way' page response

    Scenario: P2 no photo id journey - KBV mitigation - DCMAW
      Given I activate the 'disableStrategicApp' feature set
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response

    Scenario: P2 no photo id journey - KBV mitigation - Strategic app
      Given I activate the 'strategicApp' feature set
      When I submit an 'appTriage' event
      Then I get a 'identify-device' page response

    Scenario: P2 no photo id journey - KBV mitigation - F2F
      When I submit an 'f2f' event
      Then I get a 'f2f' CRI response

  Rule: KBV dropout
    Background: Start P2 no photo id KBV mitigation journey
      Given I activate the 'm2bBetaExperianKbv' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details with attributes to the CRI stub
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
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-score-0' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'no-photo-id-security-questions-find-another-way' page response with context 'dropout'

    Scenario: P2 no photo id journey - KBV dropout - DCMAW
      Given I activate the 'disableStrategicApp' feature set
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response

    Scenario: P2 no photo id journey - KBV dropout - Strategic app
      Given I activate the 'strategicApp' feature set
      When I submit an 'appTriage' event
      Then I get a 'identify-device' page response

    Scenario: P2 no photo id journey - KBV dropout - F2F
      When I submit an 'f2f' event
      Then I get a 'f2f' CRI response
