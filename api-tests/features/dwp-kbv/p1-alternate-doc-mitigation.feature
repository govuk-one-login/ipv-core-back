@Build @QualityGateIntegrationTest @QualityGateNewFeatureTest
Feature: P1 CIMIT - Alternate doc
  Background: Start web journey
    Given I activate the 'disableStrategicApp,dwpKbvTest' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response with context 'nino'

  Scenario Outline: Alternate doc mitigation via passport or DL - DWP KBV
    When I submit an <initialCri> event
    Then I get a <initialCri> CRI response
    When I submit <initialInvalidDoc> details to the CRI stub
    Then I get a <noMatchPage> page response
    When I submit a 'next' event
    Then I get a <mitigatingCri> CRI response
    When I submit <mitigatingDoc> details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
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
      | initialCri          | initialInvalidDoc                            | noMatchPage                                | mitigatingCri   | mitigatingDoc                  |
      | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'ukPassport'    | 'kenneth-passport-valid'       |
      | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'drivingLicence'| 'kenneth-driving-permit-valid' |

  Scenario Outline: Alternate doc mitigation user drops out of DWP KBV CRI via thin file
    When I submit an <initialCri> event
    Then I get a <initialCri> CRI response
    When I submit <initialInvalidDoc> details to the CRI stub
    Then I get a <noMatchPage> page response
    When I submit a 'next' event
    Then I get a <mitigatingCri> CRI response
    When I submit <mitigatingDoc> details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
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
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity

    Examples:
      | initialCri          | initialInvalidDoc                            | noMatchPage                                | mitigatingCri   | mitigatingDoc                  |
      | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'ukPassport'    | 'kenneth-passport-valid'       |
      | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'drivingLicence'| 'kenneth-driving-permit-valid' |

  Scenario Outline: Alternate doc mitigation via passport or DL - DWP KBV PIP page dropout
    When I submit an <initialCri> event
    Then I get a <initialCri> CRI response
    When I submit <initialInvalidDoc> details to the CRI stub
    Then I get a <noMatchPage> page response
    When I submit a 'next' event
    Then I get a <mitigatingCri> CRI response
    When I submit <mitigatingDoc> details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
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
    When I submit 'kenneth-score-1' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity

    Examples:
      | initialCri          | initialInvalidDoc                            | noMatchPage                                | mitigatingCri   | mitigatingDoc                  |
      | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'ukPassport'    | 'kenneth-passport-valid'       |
      | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'drivingLicence'| 'kenneth-driving-permit-valid' |

  Scenario Outline: Alternate doc mitigation via passport or DL - DWP KBV transition page dropout
    When I submit an <initialCri> event
    Then I get a <initialCri> CRI response
    When I submit <initialInvalidDoc> details to the CRI stub
    Then I get a <noMatchPage> page response
    When I submit a 'next' event
    Then I get a <mitigatingCri> CRI response
    When I submit <mitigatingDoc> details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'personal-independence-payment' page response
    When I submit a 'next' event
    Then I get a 'page-pre-dwp-kbv-transition' page response
    When I submit a 'end' event
    Then I get a 'pyi-another-way' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

    Examples:
      | initialCri          | initialInvalidDoc                            | noMatchPage                                | mitigatingCri   | mitigatingDoc                  |
      | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'ukPassport'    | 'kenneth-passport-valid'       |
      | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'drivingLicence'| 'kenneth-driving-permit-valid' |
