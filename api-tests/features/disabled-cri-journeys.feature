@Build
Feature: Disabled CRI journeys

  Rule: DCMAW is disabled

    Scenario: A P1 journey takes the user on a no photo ID journey
      Given I activate the 'dcmawOffTest,p1Journeys' feature sets
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'prove-identity-no-photo-id' page response with context 'nino'

    Scenario: A P2 journey takes the user to the document select page
      Given I activate the 'dcmawOffTest' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'page-multiple-doc-check' page response

    Scenario: Choosing DCMAW after escaping from KBV CRIs leads to technical failure
      Given I activate the 'dcmawOffTest' feature set
      Given I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'page-multiple-doc-check' page response
      When I submit a 'ukPassport' event
      Then I get a 'ukPassport' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'kbv' CRI response
      When I submit 'kenneth-score-0' details to the CRI stub
      Then I get a 'pyi-cri-escape' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-technical' page response

    Scenario: Separate session enhanced verification mitigation with DCMAW leads to technical failure
      Given the subject already has the following credentials
        | CRI        | scenario                            |
        | ukPassport | kenneth-passport-valid              |
        | address    | kenneth-current                     |
        | fraud      | kenneth-score-2                     |
        | kbv        | kenneth-needs-enhanced-verification |
      And I activate the 'dcmawOffTest' feature set
      Given I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-technical' page response

    Scenario: Same session enhanced verification mitigation with DCMAW leads to technical failure
      Given I activate the 'dcmawOffTest' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'page-multiple-doc-check' page response
      When I submit a 'drivingLicence' event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'kbv' CRI response
      When I submit 'kenneth-needs-enhanced-verification' details to the CRI stub
      Then I get a 'pyi-suggest-other-options' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-technical' page response

  Rule: F2F is disabled

    Scenario: A P1 journey for a user without a NINO routes to the escape page
      Given I activate the 'f2fDisabled,p1Journeys' feature sets
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
      When I submit an 'end' event
      Then I get a 'pyi-escape' page response

    Scenario: No photo ID leads to ineligible
      Given I activate the 'f2fDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'pyi-another-way' page response

    Scenario: Choosing not to use passport or driving licence routes to the escape page
      Given I activate the 'f2fDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit an 'access-denied' event
      Then I get a 'page-multiple-doc-check' page response
      When I submit an 'end' event
      Then I get a 'pyi-escape' page response

    Scenario Outline: Access denied from passport or driving licence CRI returns user to multidoc page
      Given I activate the 'f2fDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit an 'access-denied' event
      Then I get a 'page-multiple-doc-check' page response
      When I submit a '<cri>' event
      Then I get a '<cri>' CRI response
      When I submit an 'access-denied' event
      Then I get a 'page-multiple-doc-check' page response

      Examples:
        | cri            |
        | ukPassport     |
        | drivingLicence |

    Scenario: Separate session mitigation with enhanced verification and no photo ID leads to ineligible
      Given the subject already has the following credentials
        | CRI        | scenario                            |
        | ukPassport | kenneth-passport-valid              |
        | address    | kenneth-current                     |
        | fraud      | kenneth-score-2                     |
        | kbv        | kenneth-needs-enhanced-verification |
      And I activate the 'f2fDisabled' feature set
      Given I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'pyi-another-way' page response

    Scenario: Separate session mitigation with enhanced verification and access-denied from DCMAW leads to ineligible
      Given the subject already has the following credentials
        | CRI        | scenario                            |
        | ukPassport | kenneth-passport-valid              |
        | address    | kenneth-current                     |
        | fraud      | kenneth-score-2                     |
        | kbv        | kenneth-needs-enhanced-verification |
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
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity without a TICF VC

  Rule: BAV is disabled

    Scenario: Not having ID suitable for F2F leads to the escape page
      Given I activate the 'bavDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'pyi-escape' page response

    Scenario: Choosing to prove your identity another way on web journey leads to the escape page
      Given I activate the 'bavDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit an 'access-denied' event
      Then I get a 'page-multiple-doc-check' page response
      When I submit an 'end' event
      Then I get a 'pyi-post-office' page response
      When I submit an 'end' event
      Then I get a 'pyi-escape' page response

  Rule: HMRC and DWP KBVs are disabled

    Scenario: Experian KBV is offered first
      Given I activate the 'hmrcKbvDisabled,dwpKbvDisabled' feature sets
      When I start a new 'medium-confidence' journey
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
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'page-pre-experian-kbv-transition' page response

  Rule: DWP KBV is disabled and HMRC KBV is enabled

    Scenario: NINO then HMRC KBV is offered if user doesn't have an existing NINO
      Given I activate the 'dwpKbvDisabled,hmrcKbvBeta' feature sets
      When I start a new 'medium-confidence' journey
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
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'nino' CRI response
      When I submit a 'next' event
      Then I get an 'hmrcKbv' CRI response

    Scenario: HMRC KBV is offered if user already has a NINO
      Given I activate the 'dwpKbvDisabled,m2bBetaHmrcKbv' feature sets
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit a 'next' event
      Then I get a 'bav' CRI response
      When I submit a 'next' event
      Then I get a 'nino' CRI response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit a 'next' event
      Then I get a 'hmrcKbv' CRI response

  Rule: HMRC KBV is disabled

    Scenario: Experian KBV is offered if DWP KBV unsuitable
      Given I activate the 'dwpKbvTest' feature set
      When I start a new 'medium-confidence' journey
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
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'personal-independence-payment' page response
      When I submit an 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
