Feature: TICF failed journeys error scenarios

  Rule: Via alternate doc route
    Background: Start TICF alternate doc journey given user already has an existing TICF record
      Given there is an existing TICF record for the user with details
        | responseDelay | 0                            |
        | type          | RiskAssessment               |
        | txn           | randomUuid                   |
      When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I get an 'access_denied' OAuth error from the CRI stub
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
      When I submit 'kenneth-needs-enhanced-verification' details to the CRI stub
      Then I get a 'pyi-suggest-other-options' page response

    Scenario: TICF failed alternate doc journey - PYI_NO_MATCH
      When I submit a 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-invalid' details to the CRI stub
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity with a 'TICF' VC
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |
        | txn  | randomUuid                   |

    Scenario: TICF failed alternate doc journey - PYI_ANOTHER_WAY
      When I submit a 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get a 'pyi-post-office' page response
      When I submit a 'end' event
      Then I get a 'pyi-another-way' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity with a 'TICF' VC
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |
        | txn  | randomUuid                   |

    Scenario: TICF failed alternate doc journey - PYI_TECHNICAL
      When I submit an 'f2f' event
      Then I get a 'f2f' CRI response
      When I get an 'temporarily_unavailable' OAuth error from the CRI stub
      Then I get a 'pyi-technical' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity with a 'TICF' VC
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |
        | txn  | randomUuid                   |

  Rule: Via post-office or no-photo-id
    Background: User already has an existing TICF record
      Given there is an existing TICF record for the user with details
        | responseDelay | 0                            |
        | type          | RiskAssessment               |
        | txn           | randomUuid                   |

    Scenario: TICF failed post-office journey - PYI_ESCAPE
      When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'pyi-escape' page response
      When I submit an 'end' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity with a 'TICF' VC
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |
        | txn  | randomUuid                   |

    Scenario: TICF failed M2B journey - PYI_ESCAPE_M2B
      When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta,m2bBetaExperianKbv'
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get a 'page-multiple-doc-check' page response
      When I submit an 'end' event
      Then I get a 'pyi-post-office' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'end' event
      Then I get a 'no-photo-id-exit-find-another-way' page response
      When I submit an 'end' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity with a 'TICF' VC
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |
        | txn  | randomUuid                   |
