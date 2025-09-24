@Build
Feature: P1 Web Journeys
  Background: Start P1 journey ineligible for app
    Given I activate the 'disableStrategicApp' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response with context 'nino'

  Scenario: P1 fallback for users who fail KBV and F2F but can successfully prove their identity
    When I submit an 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'experianKbv' CRI response
    When I submit 'kenneth-needs-enhanced-verification' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
    Then I get a 'photo-id-security-questions-find-another-way' page response
    When I submit a 'f2f' event
    Then I get a 'f2f' CRI response
    When I get an error from the async CRI stub
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    When I start new 'low-confidence' journeys until I get a 'pyi-f2f-technical' page response
    Then I get a 'pyi-f2f-technical' page response
    When I submit a 'next' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'pyi-post-office' page response
    When I submit a 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-passport-valid' details with attributes to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    When I start new 'low-confidence' journeys until I get a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity

  Scenario Outline: Successful P1 journey - via <cri> and Experian KBV
    When I submit an '<cri>' event
    Then I get a '<cri>' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
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
    Then I get a 'P1' identity

    Examples:
      | cri            | details                      |
      | drivingLicence | kenneth-driving-permit-valid |
      | ukPassport     | kenneth-passport-valid       |

  Scenario: P1 Passport after multiple dropouts
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
      When I submit 'kenneth-score-1' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
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
      Then I get a 'P1' identity

  Scenario Outline: P1 journey - thin file via Experian KBV
    When I submit an '<cri>' event
    Then I get a '<cri>' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'experianKbv' CRI response
    When I submit 'kenneth-score-0' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
    Then I get a 'photo-id-security-questions-find-another-way' page response with context 'dropout'

    Examples:
      | cri            | details                      |
      | drivingLicence | kenneth-driving-permit-valid |
      | ukPassport     | kenneth-passport-valid       |

  Scenario: P1 unsuccessful KBV questions for low confidence users with photo ID
    When I submit an 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'experianKbv' CRI response
    When I submit 'kenneth-needs-enhanced-verification' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
    Then I get a 'photo-id-security-questions-find-another-way' page response

  Scenario Outline: P1 journey used when both P1 and P2 are present in JAR request
    When I start a new 'low-medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response with context 'nino'
    When I submit an '<cri>' event
    Then I get a '<cri>' CRI response
    When I submit '<details>' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
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
    Then I get a 'P1' identity

    Examples:
      | cri            | details                      |
      | drivingLicence | kenneth-driving-permit-valid |
      | ukPassport     | kenneth-passport-valid       |

  Rule: Route through DWP KBV
    Background: Enable DWP KBV
      Given I activate the 'dwpKbvTest' feature set

    Scenario Outline: Successful P1 journey - via <cri> and DWP KBV
      When I submit an '<cri>' event
      Then I get a '<cri>' CRI response
      When I submit '<details>' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-1' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
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

      Examples:
        | cri            | details                      |
        | drivingLicence | kenneth-driving-permit-valid |
        | ukPassport     | kenneth-passport-valid       |

    Scenario Outline: P1 journey - thin file via DWP KBV
      When I submit an '<cri>' event
      Then I get a '<cri>' CRI response
      When I submit '<details>' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-1' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'personal-independence-payment' page response
      When I submit a 'next' event
      Then I get a 'page-pre-dwp-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'dwpKbv' CRI response
      When I call the CRI stub with attributes and get an 'invalid_request' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
      Then I get a 'page-different-security-questions' page response
      When I submit a 'next' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity

      Examples:
        | cri            | details                      |
        | drivingLicence | kenneth-driving-permit-valid |
        | ukPassport     | kenneth-passport-valid       |

    Scenario Outline: P1 journey - <error> from DWP CRI
      When I submit an 'ukPassport' event
      Then I get a 'ukPassport' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-1' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'personal-independence-payment' page response
      When I submit a 'next' event
      Then I get a 'page-pre-dwp-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'dwpKbv' CRI response
      When I call the CRI stub with attributes and get an '<error>' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
      Then I get a 'pyi-technical' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

      Examples:
        | error                     |
        | temporarily_unavailable   |
