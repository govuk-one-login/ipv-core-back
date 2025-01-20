@Build
Feature: Authoritative source checks with driving licence CRI

  Scenario Outline: Journey through DCMAW with driving licence requires authoritative source check
    Given I activate the 'drivingLicenceAuthCheck,p1Journeys' feature sets
    When I start a new '<journey-type>' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
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

  Scenario Outline: Journey with auth source check that attracts a CI leads to a mitigation journey
    Given I activate the 'drivingLicenceAuthCheck,p1Journeys' feature sets
    When I start a new '<journey-type>' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-needs-alternate-doc' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'pyi-driving-licence-no-match-another-way' page response
    When I submit an 'end' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

    Examples:
      | journey-type       |
      | low-confidence    |
      | medium-confidence |

  Scenario Outline: Separate session enhanced verification mitigation with DCMAW and driving licence requires auth source check
    Given I activate the 'drivingLicenceAuthCheck' feature set
    And the subject already has the following credentials
      | CRI        | scenario                            |
      | ukPassport | kenneth-passport-valid              |
      | address    | kenneth-current                     |
      | fraud      | kenneth-score-2                     |
      | kbv        | kenneth-needs-enhanced-verification |

    # Return journey
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
    Then I get a 'drivingLicence' CRI response
    When I submit '<dl_details>' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a '<page_response>' page response
    Examples:
      | dl_details                                 | page_response      |
      | kenneth-driving-permit-valid               | page-dcmaw-success |
      | kenneth-driving-permit-needs-alternate-doc | pyi-no-match       |

  Scenario Outline: Same session enhanced verification mitigation
    Given I activate the 'drivingLicenceAuthCheck' feature set
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
    Then I get a 'pyi-suggest-other-options' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
    Then I get a 'drivingLicence' CRI response
    When I submit '<dl_details>' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a '<page_response>' page response
    Examples:
      | dl_details                                 | page_response    |
      | kenneth-driving-permit-valid               | page-ipv-success |
      | kenneth-driving-permit-needs-alternate-doc | pyi-no-match     |

  Scenario Outline: KBV thin file
    Given I activate the 'drivingLicenceAuthCheck' feature set
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
    When I submit 'kenneth-score-0' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'pyi-cri-escape' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I submit '<dl_details>' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a '<page_response>' page response
    Examples:
      | dl_details                                 | page_response    |
      | kenneth-driving-permit-valid               | page-ipv-success |
      | kenneth-driving-permit-needs-alternate-doc | pyi-no-match     |

  Scenario: Auth source check is not required if user already has a good driving licence VC
    Given I activate the 'drivingLicenceAuthCheck' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
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
    When I submit 'kenneth-needs-enhanced-verification' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'pyi-suggest-other-options' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
    Then I get a 'page-ipv-success' page response

  Scenario: Auth source check is required if doc identifiers do not match
    Given I activate the 'drivingLicenceAuthCheck' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response
    When I submit a 'drivingLicence' event
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-dva-valid' details to the CRI stub
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
    Then I get a 'pyi-suggest-other-options' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'page-ipv-success' page response

  Scenario: Reverification journeys with a driving licence require an auth source check
    Given I activate the 'drivingLicenceAuthCheck' feature set
    And the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    When I start a new 'reverification' journey
    Then I get a 'you-can-change-security-code-method' page response
    When I submit a 'next' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'page-dcmaw-success' page response

  Scenario Outline: Change of details journey through DCMAW with driving licence requires auth source check
    Given I activate the 'drivingLicenceAuthCheck' feature set
    And the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'update-details' event
    Then I get a 'update-details' page response
    When I submit a '<update-type>' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-changed-given-name-driving-permit-valid' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'page-dcmaw-success' page response with context '<context>'

    Examples:
      | update-type             | context      |
      | given-names-only        | coiNoAddress |
      | given-names-and-address | coiAddress   |

  Scenario Outline: Change of details journey that attracts an invalid doc CI from auth source check
    Given I activate the 'drivingLicenceAuthCheck' feature set
    And the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'update-details' event
    Then I get a 'update-details' page response
    When I submit a '<update-type>' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-needs-alternate-doc' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'

    Examples:
      | update-type             |
      | given-names-only        |
      | given-names-and-address |
