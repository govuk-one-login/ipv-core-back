@Build
Feature: CIMIT - Alternate doc
  Background:
    Given I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-multiple-doc-check' page response

  Scenario Outline: Alternate doc mitigation via passport or DL
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
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | initialCri          | initialInvalidDoc                            | noMatchPage                                | mitigatingCri   | mitigatingDoc                  |
      | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'ukPassport'    | 'kenneth-passport-valid'       |
      | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'drivingLicence'| 'kenneth-driving-permit-valid' |

  Scenario Outline: Alternate doc mitigation via passport or DL - DWP KBV
    Given I start a new 'medium-confidence' journey with feature set 'dwpKbvTest'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-multiple-doc-check' page response
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
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'personal-independence-payment' page response
    When I submit a 'next' event
    Then I get a 'page-pre-dwp-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'dwpKbv' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | initialCri          | initialInvalidDoc                            | noMatchPage                                | mitigatingCri   | mitigatingDoc                  |
      | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'ukPassport'    | 'kenneth-passport-valid'       |
      | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'drivingLicence'| 'kenneth-driving-permit-valid' |

  Scenario Outline: Alternate doc mitigation via passport or DL - DWP KBV PIP page dropout
    Given I start a new 'medium-confidence' journey with feature set 'dwpKbvTest'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-multiple-doc-check' page response
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
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'personal-independence-payment' page response
    When I submit a 'end' event
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | initialCri          | initialInvalidDoc                            | noMatchPage                                | mitigatingCri   | mitigatingDoc                  |
      | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'ukPassport'    | 'kenneth-passport-valid'       |
      | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'drivingLicence'| 'kenneth-driving-permit-valid' |

  Scenario Outline: Alternate doc mitigation via passport or DL - DWP KBV transition page dropout
    Given I start a new 'medium-confidence' journey with feature set 'dwpKbvTest'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-multiple-doc-check' page response
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
    When I submit 'kenneth-score-2' details to the CRI stub
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

  Scenario Outline: Alternate doc mitigation via passport or DL - HMRC KBV
    Given I start a new 'medium-confidence' journey with feature set 'm2bBetaHmrcKbv'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-multiple-doc-check' page response
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
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'nino' CRI response
    When I submit 'kenneth' details to the CRI stub
    Then I get a 'hmrcKbv' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | initialCri          | initialInvalidDoc                            | noMatchPage                                | mitigatingCri   | mitigatingDoc                  |
      | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'ukPassport'    | 'kenneth-passport-valid'       |
      | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'drivingLicence'| 'kenneth-driving-permit-valid' |

  Scenario Outline: Alternate doc mitigation user drops out of HMRC KBV CRI via thin file or failed checks - HMRC KBV
    Given I start a new 'medium-confidence' journey with feature set 'm2bBetaHmrcKbv'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-multiple-doc-check' page response
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
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'nino' CRI response
    When I submit 'kenneth' details to the CRI stub
    Then I get a 'hmrcKbv' CRI response
    When I get an 'invalid_request' OAuth error from the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | initialCri          | initialInvalidDoc                            | noMatchPage                                | mitigatingCri   | mitigatingDoc                  |
      | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'ukPassport'    | 'kenneth-passport-valid'       |
      | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'drivingLicence'| 'kenneth-driving-permit-valid' |

  Scenario Outline: Mitigation of alternate-doc CI via <mitigating-cri> when user initially drops out of <mitigating-cri>
    When I submit a '<initial-cri>' event
    Then I get a '<initial-cri>' CRI response
    When I submit '<initial-invalid-doc>' details to the CRI stub
    Then I get a '<no-match-page>' page response
    When I submit a 'next' event
    Then I get a '<mitigating-cri>' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'prove-identity-no-other-photo-id' page response with context '<prove-identity-no-other-photo-id-context>'
    When I submit a 'back' event
    Then I get a '<mitigating-cri>' CRI response
    When I submit '<mitigating-doc>' details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | initial-cri    | initial-invalid-doc                        | no-match-page                            | mitigating-cri | mitigating-doc               | prove-identity-no-other-photo-id-context |
      | ukPassport     | kenneth-passport-needs-alternate-doc       | pyi-passport-no-match-another-way        | drivingLicence | kenneth-driving-permit-valid | drivingLicence                           |
      | drivingLicence | kenneth-driving-permit-needs-alternate-doc | pyi-driving-licence-no-match-another-way | ukPassport     | kenneth-passport-valid       | passport                                 |

  Scenario: Returns P0 when user continues to service from prove-identity-no-other-photo-id page during CI mitigation
    When I submit a 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I submit 'kenneth-passport-needs-alternate-doc' details to the CRI stub
    Then I get a 'pyi-passport-no-match-another-way' page response
    When I submit a 'next' event
    Then I get a 'drivingLicence' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'prove-identity-no-other-photo-id' page response with context 'drivingLicence'
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
