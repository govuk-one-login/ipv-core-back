@Build
Feature: P2 CIMIT - Alternate doc
  Rule: No existing identity
    Background:
      Given I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
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
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | initialCri          | initialInvalidDoc                            | noMatchPage                                | mitigatingCri   | mitigatingDoc                  |
        | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'ukPassport'    | 'kenneth-passport-valid'       |
        | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'drivingLicence'| 'kenneth-driving-permit-valid' |

    Scenario Outline: Alternate doc mitigation via passport or DL - separate session
      When I submit an <initialCri> event
      Then I get a <initialCri> CRI response
      When I submit <initialInvalidDoc> details to the CRI stub
      Then I get a <noMatchPage> page response
      When I submit a 'next' event
      Then I get a <mitigatingCri> CRI response

      # User drops out of previous CRI without mitigating and starts a new journey
      Given I start a new 'medium-confidence' journey
      Then I get a <separateSessionNoMatch> page response
      When I submit a 'next' event
      Then I get a <mitigationStart> page response
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
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | initialCri          | initialInvalidDoc                            | noMatchPage                                | separateSessionNoMatch         | mitigationStart                     |mitigatingCri   | mitigatingDoc                  |
        | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'pyi-driving-licence-no-match' | 'pyi-continue-with-passport'        | 'ukPassport'    | 'kenneth-passport-valid'       |
        | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'pyi-passport-no-match'        | 'pyi-continue-with-driving-licence' |'drivingLicence'| 'kenneth-driving-permit-valid' |

    Scenario Outline: Alternate doc mitigation via passport or DL - DWP KBV
      Given I activate the 'dwpKbvTest' feature set
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
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | initialCri          | initialInvalidDoc                            | noMatchPage                                | mitigatingCri   | mitigatingDoc                  |
        | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'ukPassport'    | 'kenneth-passport-valid'       |
        | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'drivingLicence'| 'kenneth-driving-permit-valid' |

    Scenario Outline: Alternate doc mitigation user drops out of DWP KBV CRI via thin file
      Given I activate the 'dwpKbvTest' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
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
      When I call the CRI stub with attributes and get an 'invalid_request' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-different-security-questions' page response
      When I submit a 'next' event
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
        | initialCri          | initialInvalidDoc                            | noMatchPage                                | mitigatingCri   | mitigatingDoc                  |
        | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'ukPassport'    | 'kenneth-passport-valid'       |
        | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'drivingLicence'| 'kenneth-driving-permit-valid' |

    Scenario Outline: Alternate doc mitigation via passport or DL - DWP KBV PIP page dropout
      Given I activate the 'dwpKbvTest' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
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
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
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
      Given I activate the 'dwpKbvTest' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
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

    Scenario Outline: Mitigation of alternate-doc CI via <mitigating-cri> when user initially drops out of <mitigating-cri>
      When I submit a '<initial-cri>' event
      Then I get a '<initial-cri>' CRI response
      When I submit '<initial-invalid-doc>' details to the CRI stub
      Then I get a '<no-match-page>' page response
      When I submit a 'next' event
      Then I get a '<mitigating-cri>' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
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
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
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
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'prove-identity-no-other-photo-id' page response with context 'drivingLicence'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

  Rule: Existing identity
    Scenario: Mitigating when a user already has an identity should be subject to a COI check
      Given the subject already has the following credentials
        | CRI        | scenario               |
        | ukPassport | kenneth-passport-valid |
        | address    | kenneth-current        |
        | fraud      | kenneth-score-2        |
        | kbv        | kenneth-score-2        |

      # First return journey that collects a CI
      And I activate the 'drivingLicenceAuthCheck' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit an 'update-details' event
      Then I get an 'update-details' page response
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response
      When I submit an 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-needs-alternate-doc' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'

      # Seconds return journey to mitigate CI
      Given I start a new 'medium-confidence' journey
      Then I get a 'pyi-driving-licence-no-match' page response
      When I submit a 'next' event
      Then I get a 'pyi-continue-with-passport' page response
      When I submit a 'next' event
      Then I get a 'ukPassport' CRI response
      When I submit 'lora-passport-valid' details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
      Then I get an 'address' CRI response
      When I submit 'lora-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'lora-score-2' details to the CRI stub
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'kbv' CRI response
      When I submit 'lora-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'pyi-no-match' page response
