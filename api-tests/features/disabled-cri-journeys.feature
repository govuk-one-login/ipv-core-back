@Build
Feature: Disabled CRI journeys
  Background: Disable the strategic app
    Given I activate the 'disableStrategicApp' feature set

  Rule: DCMAW is disabled

    Scenario: A P1 journey takes the user on a no photo ID journey
      Given I activate the 'dcmawOffTest' feature sets
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'prove-identity-no-photo-id' page response with context 'nino'

    Scenario: A P2 journey takes the user to the document select page
      Given I activate the 'dcmawOffTest' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'page-multiple-doc-check' page response

    Scenario: Choosing DCMAW after escaping from KBV CRIs leads to technical failure
      Given I activate the 'dcmawOffTest' feature set
      Given I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
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
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-score-0' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'photo-id-security-questions-find-another-way' page response with context 'dropout'
      When I submit an 'appTriage' event
      Then I get a 'pyi-technical' page response

    Scenario: Separate session enhanced verification mitigation with DCMAW leads to technical failure
      Given the subject already has the following credentials
        | CRI         | scenario                            |
        | ukPassport  | kenneth-passport-valid              |
        | address     | kenneth-current                     |
        | fraud       | kenneth-score-2                     |
        | experianKbv | kenneth-needs-enhanced-verification |
      And I activate the 'dcmawOffTest' feature set
      Given I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-technical' page response

    Scenario: Same session enhanced verification mitigation with DCMAW leads to technical failure
      Given I activate the 'dcmawOffTest' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'page-multiple-doc-check' page response
      When I submit a 'drivingLicence' event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-needs-enhanced-verification' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'photo-id-security-questions-find-another-way' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-technical' page response

  Rule: F2F is disabled

    Scenario: A P1 journey for a user without a NINO routes to the escape page
      Given I activate the 'f2fDisabled' feature sets
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
      When I submit an 'end' event
      Then I get a 'pyi-escape' page response

    Scenario: No photo ID leads to ineligible
      Given I activate the 'f2fDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'pyi-another-way' page response

    Scenario: Choosing not to use passport or driving licence routes to the escape page
      Given I activate the 'f2fDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit an 'access-denied' event
      Then I get a 'page-multiple-doc-check' page response
      When I submit an 'end' event
      Then I get a 'pyi-escape' page response

    Scenario Outline: Choosing another way after access-denied from passport or DL CRIs leads to escape page
      Given I activate the 'f2fDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit an 'access-denied' event
      Then I get a 'page-multiple-doc-check' page response
      When I submit a '<cri>' event
      Then I get a '<cri>' CRI response
      When I submit an 'access-denied' event
      Then I get a 'prove-identity-another-type-photo-id' page response with context '<context>'
      When I submit an 'f2f' event
      Then I get a 'pyi-escape' page response

      Examples:
        | cri            | context        |
        | ukPassport     | passport       |
        | drivingLicence | drivingLicence |

    Scenario: Separate session mitigation with enhanced verification and no photo ID leads to ineligible
      Given the subject already has the following credentials
        | CRI         | scenario                            |
        | ukPassport  | kenneth-passport-valid              |
        | address     | kenneth-current                     |
        | fraud       | kenneth-score-2                     |
        | experianKbv | kenneth-needs-enhanced-verification |
      And I activate the 'f2fDisabled' feature set
      Given I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'pyi-another-way' page response

    Scenario: Separate session mitigation with enhanced verification and access-denied from DCMAW leads to ineligible
      Given the subject already has the following credentials
        | CRI         | scenario                            |
        | ukPassport  | kenneth-passport-valid              |
        | address     | kenneth-current                     |
        | fraud       | kenneth-score-2                     |
        | experianKbv | kenneth-needs-enhanced-verification |
      And I activate the 'f2fDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit an 'access-denied' event
      Then I get a 'pyi-another-way' page response

  Rule: TICF is disabled

    Scenario: A P2 journey is still successful
      Given I activate the 'ticfDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity without a TICF VC

  Rule: BAV is disabled

    Scenario: Not having ID suitable for F2F leads to the escape page
      Given I activate the 'bavDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'pyi-escape' page response

    Scenario: Choosing to prove your identity another way on web journey leads to the escape page
      Given I activate the 'bavDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit an 'access-denied' event
      Then I get a 'page-multiple-doc-check' page response
      When I submit an 'end' event
      Then I get a 'pyi-post-office' page response
      When I submit an 'end' event
      Then I get a 'pyi-escape' page response

  Rule: DWP KBVs are disabled or unsuitable
    Background: User starts a web journey to KBV
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit an 'access-denied' event
      Then I get a 'page-multiple-doc-check' page response
      When I submit a 'ukPassport' event
      Then I get a 'ukPassport' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response

    Scenario: Experian KBV is offered first
      Given I activate the 'dwpKbvDisabled' feature sets
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-pre-experian-kbv-transition' page response

    Scenario: Experian KBV is offered if DWP KBV unsuitable
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'personal-independence-payment' page response
      When I submit an 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
