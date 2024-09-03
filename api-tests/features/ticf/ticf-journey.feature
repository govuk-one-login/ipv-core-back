@Build # TODO: add ticf env variables to build (see run-tests.sh)
Feature: TICF journey
  Scenario: TICF CRI request - with no CI same session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
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
    Then I get a 'P2' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |

  Scenario: TICF CRI request - with no CI in separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
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
    Then I get a 'P2' identity

    # New journey with the same user id
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-reuse' page response
    And my proven user details match
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |

  Scenario: TICF CRI request - with no CI initially and then a CI in a separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
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
    Then I get a 'P2' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |

    # New journey with the same user id
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
      | cis           | BREACHING                    |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  | BREACHING                    |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |

  Scenario: TICF CRI request - with no CI initially then timeout in separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
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
    Then I get a 'P2' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |

    # New journey with the same user id
    # Submitting no txn results in a timeout when the user's TICF record is requested
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           |                              |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-reuse' page response
    And my proven user details match
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |
      | txn  |                              |

  Scenario: TICF CRI request - with CI same session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
      | cis           | BREACHING                    |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  | BREACHING                    |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |

  Scenario: TICF CRI request - with CI separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
      | cis           | BREACHING                    |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  | BREACHING                    |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |

    # New journey with the same user id
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
      | cis           | BREACHING                    |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'pyi-no-match' page response
    Then I get a 'P0' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  | BREACHING                    |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |

  Scenario: TICF CRI request - with CI initially then no CI in separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
      | cis           | BREACHING                    |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  | BREACHING                    |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |

    # New journey with the same user id
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |

  Scenario: TICF CRI request - for timeout and no CI initially then no CI in separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           |                              |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
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
    Then I get a 'P2' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |
      | txn  |                              |

    # New journey with the same user id
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-reuse' page response
    And my proven user details match
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |

  Scenario: TICF CRI request - for timeout then CI in separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           |                              |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
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
    Then I get a 'P2' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |
      | txn  |                              |

    # New journey with the same user id
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
      | cis           | BREACHING                    |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  | BREACHING                    |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |

  Scenario: TICF CRI request - response delay less than 5s
    Given there is an existing TICF record for the user with details
      | responseDelay | 4                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
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
    Then I get a 'P2' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |

  Scenario: TICF CRI request - response delay more than 5s
    Given there is an existing TICF record for the user with details
      | responseDelay | 10                           |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
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
    Then I get a 'P2' identity without a 'TICF' VC

  Scenario: TICF CRI request - F2F separate session check
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
    Given I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'page-ipv-identity-postoffice-start' page response
    When I submit a 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-passport-valid' details to the async CRI stub
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response with feature set 'ticfCriBeta'
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity with a 'TICF' VC
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |
      | txn  | randomUuid                   |
