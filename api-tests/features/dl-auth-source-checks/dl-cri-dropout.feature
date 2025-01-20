@Build
Feature: Dropping out of authoritative source checks with DL CRI (e.g. due to incorrect details)
  Background: Activate the featureSet
    Given I activate the 'drivingLicenceAuthCheck,p1Journeys' feature sets

  Scenario Outline: User backs out of driving licence CRI is able to return to DCMAW and re-scan their DL
    When I start a new '<journey-type>' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub with attributes and get an 'access_denied' OAuth error
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'uk-driving-licence-details-not-correct' page response
    When I submit a 'next' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'page-dcmaw-success' page response

    Examples:
      | journey-type      |
      | low-confidence    |
      | medium-confidence |

  Scenario Outline: User backs out of driving licence CRI and returns to DCMAW with a passport - identity has only one DCMAW VC
    When I start a new '<journey-type>' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub with attributes and get an 'access_denied' OAuth error
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'uk-driving-licence-details-not-correct' page response
    When I submit a 'next' event
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
    Then I get a '<expected-identity>' identity
    And I have a dcmaw VC without 'drivingPermit' details

    Examples:
      | journey-type      | expected-identity |
      | low-confidence    | P1                |
      | medium-confidence | P2                |

  Scenario Outline: User backs out of driving licence CRI is able to prove their identity another way - via F2F and has no dcmaw VC
    When I start a new '<journey-type>' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub with attributes and get an 'access_denied' OAuth error
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'uk-driving-licence-details-not-correct' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-another-way' page response
    When I submit a 'postOffice' event
    Then I get a 'page-ipv-identity-postoffice-start' page response with context '<context>'
    When I submit a 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-passport-valid' details with attributes to the async CRI stub
      | Attribute          | Values                     |
      | evidence_requested | <evidence-requested-value> |
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    When I start a new '<journey-type>' journey and return to a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a '<expected-identity>' identity without a 'dcmaw' VC

    Examples:
      | journey-type      | context    | evidence-requested-value                    | expected-identity |
      | low-confidence    | lastChoice | {"scoringPolicy":"gpg45","strengthScore":2} | P1                |
      | medium-confidence | null       | {"scoringPolicy":"gpg45","strengthScore":3} | P2                |

  Scenario Outline: User backs out of DL CRI and selects to return to the RP - should not have a DCMAW VC
    When I start a new '<journey-type>' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub with attributes and get an 'access_denied' OAuth error
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'uk-driving-licence-details-not-correct' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-another-way' page response
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

    Examples:
      | journey-type      |
      | low-confidence    |
      | medium-confidence |

  Rule: Change of details journey
    Background: User has existing credentials and starts an update details journey
      And the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-passport-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit a 'update-details' event
      Then I get a 'update-details' page response

    Scenario: Change of name only journey - User backs out of DL CRI - Returns to DCMAW to use passport
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I call the CRI stub with attributes and get an 'access_denied' OAuth error
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'uk-driving-licence-details-not-correct' page response
      When I submit a 'next' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-given-name-score-2' details to the CRI stub
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And I have a dcmaw VC without 'drivingPermit' details

    Scenario: Change of name and address journey - User backs out of DL CRI - Returns to DCMAW to use passport
      When I submit a 'family-name-and-address' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I call the CRI stub with attributes and get an 'access_denied' OAuth error
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'uk-driving-licence-details-not-correct' page response
      When I submit a 'next' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-family-name-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-changed' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-family-name-and-address-score-2' details to the CRI stub
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And I have a dcmaw VC without 'drivingPermit' details

    Scenario Outline: Change of details - return to RP with no identity
      When I submit a '<update-type>' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I call the CRI stub with attributes and get an 'access_denied' OAuth error
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'uk-driving-licence-details-not-correct' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-another-way' page response with context 'noF2f'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

      Examples:
        | update-type             |
        | given-names-only        |
        | given-names-and-address |

  Rule: Separate session enhanced verification mitigation with DCMAW + DL auth source check
    Background: User returns with an enhanced verification CI and mitigates with DCMAW but user drops out of DL CRI
      And the subject already has the following credentials
        | CRI        | scenario                            |
        | ukPassport | kenneth-passport-valid              |
        | address    | kenneth-current                     |
        | fraud      | kenneth-score-2                     |
        | kbv        | kenneth-needs-enhanced-verification |
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
      Then I get a 'drivingLicence' CRI response
      When I call the CRI stub with attributes and get an 'access_denied' OAuth error
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'uk-driving-licence-details-not-correct' page response

    Scenario: User is able to return to DCMAW
      When I submit a 'next' event
      Then I get a 'dcmaw' CRI response

    Scenario: User is able to mitigate via F2f
      When I submit an 'end' event
      Then I get a 'prove-identity-another-way' page response
      When I submit a 'postOffice' event
      Then I get a 'pyi-post-office' page response

    Scenario: User returns to RP without identity
      When I submit an 'end' event
      Then I get a 'prove-identity-another-way' page response
      When I submit an 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

  Rule: Same session enhanced verification mitigation with DCMAW + DL auth source check
    Background: User gets an enhanced verification CI in the same session
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
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
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'kbv' CRI response
      When I submit 'kenneth-needs-enhanced-verification' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'photo-id-security-questions-find-another-way' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
      Then I get a 'drivingLicence' CRI response
      When I call the CRI stub with attributes and get an 'access_denied' OAuth error
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'uk-driving-licence-details-not-correct' page response

    Scenario: User is able to return to DCMAW
      When I submit a 'next' event
      Then I get a 'dcmaw' CRI response

    Scenario: User is able to mitigate via F2f
      When I submit an 'end' event
      Then I get a 'prove-identity-another-way' page response
      When I submit a 'postOffice' event
      Then I get a 'pyi-post-office' page response

    Scenario: User returns to RP without identity
      When I submit an 'end' event
      Then I get a 'prove-identity-another-way' page response
      When I submit an 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
