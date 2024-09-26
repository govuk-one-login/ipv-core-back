@Build
Feature: TICF failed/error journeys

  Rule: Via enhanced-verification journey
    Background: Start TICF enhanced verification journey
      When I start a new 'medium-confidence' journey
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

    Scenario: TICF failed enhanced-verification journey - PYI_NO_MATCH
      When I submit a 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-with-breaching-ci' details to the CRI stub
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |

    Scenario: TICF failed enhanced-verification journey - PYI_ANOTHER_WAY
      When I submit a 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get a 'pyi-post-office' page response
      When I submit a 'end' event
      Then I get a 'pyi-another-way' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |

    Scenario: TICF failed enhanced-verification journey - PYI_TECHNICAL
      When I submit an 'f2f' event
      Then I get a 'f2f' CRI response
      When I get an 'temporarily_unavailable' OAuth error from the CRI stub
      Then I get a 'pyi-technical' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |

  Rule: Via post-office
    Scenario: TICF failed post-office journey - PYI_ESCAPE
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'pyi-escape' page response
      When I submit an 'end' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |

  Rule: Via no-photo-id
    Scenario: TICF failed M2B journey - PYI_ESCAPE_M2B
      When I start a new 'medium-confidence' journey with feature set 'm2bBetaExperianKbv'
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
      Then I get a 'P0' identity
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |
