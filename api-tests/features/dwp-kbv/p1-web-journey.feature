@Build @QualityGateIntegrationTest @QualityGateNewFeatureTest
Feature: P1 Web Journeys
  Background: Set feature sets
    Given I activate the 'disableStrategicApp,dwpKbvTest' feature sets

  Rule: Passport/DL web journey
    Background: Start P1 journey ineligible for app
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'page-multiple-doc-check' page response with context 'nino'

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

  Rule: No Photo ID web journey
    Background: Start no photo ID journey to DWP KBV
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
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

    Scenario: P1 No Photo Id Journey - DWP KBV
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

    Scenario: P1 No Photo Id Journey user drops out of DWP KBV CRI via thin file or failed checks - DWP KBV
      When I submit a 'next' event
      Then I get a 'page-pre-dwp-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'dwpKbv' CRI response
      When I call the CRI stub with attributes and get an 'access_denied' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
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

    Scenario: P1 No Photo Id Journey - DWP KBV PIP page dropout
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
      Then I get a 'P1' identity

    Scenario: P1 No Photo Id Journey - DWP KBV transition page dropout
      When I submit a 'next' event
      Then I get a 'page-pre-dwp-kbv-transition' page response
      When I submit a 'end' event
      Then I get a 'no-photo-id-security-questions-find-another-way' page response with context 'dropout'
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
