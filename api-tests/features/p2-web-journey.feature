@Build
Feature: P2 Web document journey
  Background: Start P2 journey and ineligible for the app
    Given I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response

  Scenario Outline: Successful P2 identity via Web using <cri>
    When I submit a '<cri>' event
    Then I get a '<cri>' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And an 'IPV_IDENTITY_ISSUED' audit event was recorded [local only]

    Examples:
      | cri            | details                      |
      | drivingLicence | kenneth-driving-permit-valid |
      | ukPassport     | kenneth-passport-valid       |

  Scenario Outline: Successful P2 identity via Web using <cri> - DWP KBV
    Given I activate the 'dwpKbvTest' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response
    When I submit a '<cri>' event
    Then I get a '<cri>' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'personal-independence-payment' page response
    When I submit a 'next' event
    Then I get a 'page-pre-dwp-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'dwpKbv' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | cri            | details                      |
      | drivingLicence | kenneth-driving-permit-valid |
      | ukPassport     | kenneth-passport-valid       |

  Scenario Outline: Successful P2 identity via Web using <cri> - DWP KBV PIP page dropout
    Given I activate the 'dwpKbvTest' feature sets
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response
    When I submit a '<cri>' event
    Then I get a '<cri>' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'personal-independence-payment' page response
    When I submit a 'end' event
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | cri            | details                      |
      | drivingLicence | kenneth-driving-permit-valid |
      | ukPassport     | kenneth-passport-valid       |

  Scenario Outline: Successful P2 identity via Web using - DWP KBV transition page dropout
    Given I activate the 'dwpKbvTest' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response
    When I submit a '<cri>' event
    Then I get a '<cri>' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'personal-independence-payment' page response
    When I submit a 'next' event
    Then I get a 'page-pre-dwp-kbv-transition' page response
    When I submit a 'end' event
    Then I get a 'pyi-cri-escape' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | cri            | details                      |
      | drivingLicence | kenneth-driving-permit-valid |
      | ukPassport     | kenneth-passport-valid       |

  Scenario Outline: User drops out of DWP KBV CRI via thin file or failed checks using <cri> - DWP KBV
    Given I activate the 'dwpKbvTest' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response
    When I submit a '<cri>' event
    Then I get a '<cri>' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'personal-independence-payment' page response
    When I submit a 'next' event
    Then I get a 'page-pre-dwp-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'dwpKbv' CRI response
    When I call the CRI stub with attributes and get an 'access_denied' OAuth error
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | cri            | details                      |
      | drivingLicence | kenneth-driving-permit-valid |
      | ukPassport     | kenneth-passport-valid       |

  Scenario Outline: Successful P2 identity via Web using <cri> - HMRC KBV
    Given I activate the 'm2bBetaHmrcKbv' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response
    When I submit a '<cri>' event
    Then I get a '<cri>' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'nino' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'hmrcKbv' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | cri            | details                      |
      | drivingLicence | kenneth-driving-permit-valid |
      | ukPassport     | kenneth-passport-valid       |

  Scenario Outline: User drops out of HMRC KBV CRI via thin file or failed checks using <cri> - HMRC KBV
    Given I activate the 'm2bBetaHmrcKbv' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response
    When I submit a '<cri>' event
    Then I get a '<cri>' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'nino' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'hmrcKbv' CRI response
    When I call the CRI stub with attributes and get an 'access_denied' OAuth error
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | cri            | details                      |
      | drivingLicence | kenneth-driving-permit-valid |
      | ukPassport     | kenneth-passport-valid       |

  Scenario Outline: User drops out of NINO CRI after <cri> - HMRC KBV
    Given I activate the 'm2bBetaHmrcKbv' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response
    When I submit a '<cri>' event
    Then I get a '<cri>' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'nino' CRI response
    When I submit 'kenneth-score-0' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | cri            | details                      |
      | drivingLicence | kenneth-driving-permit-valid |
      | ukPassport     | kenneth-passport-valid       |

  Scenario Outline: Allows use of <alternative-doc-cri> when user drops out of <initial-cri> CRI
    When I submit a '<initial-cri>' event
    Then I get a '<initial-cri>' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'prove-identity-another-type-photo-id' page response with context '<prove-identity-another-type-photo-id-context>'
    When I submit a 'otherPhotoId' event
    Then I get a '<alternative-doc-cri>' CRI response
    When I submit '<alternative-doc>' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | initial-cri    | alternative-doc-cri | alternative-doc              | prove-identity-another-type-photo-id-context |
      | ukPassport     | drivingLicence      | kenneth-driving-permit-valid | passport                                     |
      | drivingLicence | ukPassport          | kenneth-passport-valid       | drivingLicence                               |

  Scenario: User is able to continue to service from the prove-identity-another-type-photo-id page without an identity
    When I submit a 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'prove-identity-another-type-photo-id' page response with context 'passport'
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

  Scenario: User can use F2F from the prove-identity-another-type-photo-id page to receive an identity
    When I submit a 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'prove-identity-another-type-photo-id' page response with context 'passport'
    When I submit an 'f2f' event
    Then I get a 'pyi-post-office' page response
    When I submit a 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-driving-permit-valid' details with attributes to the async CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario Outline: Failed P2 journey via Web using <cri>
    When I submit a '<cri>' event
    Then I get a '<cri>' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-0-breaching' details to the CRI stub
    Then I get a 'pyi-no-match' page response

    Examples:
      | cri            | details                      |
      | drivingLicence | kenneth-driving-permit-valid |
      | ukPassport     | kenneth-passport-valid       |

  Scenario: Driving permit with fraud score 1 results in failed journey
    When I submit a 'drivingLicence' event
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details to the CRI stub
    Then I get a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

  Rule: User drops out of KBV CRI via thin file or failed checks
    Background: Navigate to KBV CRI
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

    Scenario: KBV score zero - user is able to receive identity via DCMAW
      When I submit 'kenneth-score-0' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'pyi-cri-escape' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: KBV score zero - user is able to receive identity via F2F
      When I submit 'kenneth-score-0' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'pyi-cri-escape' page response
      When I submit an 'f2f' event
      Then I get a 'f2f' CRI response
      When I submit 'kenneth-passport-valid' details with attributes to the async CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":0} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: KBV score zero - user is able to receive identity via F2F after dropping out of DCMAW
      When I submit 'kenneth-score-0' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'pyi-cri-escape' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'pyi-post-office' page response
      When I submit an 'next' event
      Then I get a 'f2f' CRI response
      When I submit 'kenneth-passport-valid' details with attributes to the async CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":0} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
