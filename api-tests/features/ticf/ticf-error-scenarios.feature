# TODO: re-name these scenarios + features + file name
@Build
Feature: TICF error scenarios
  Scenario: TICF error scenario - PYI_NO_MATCH
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
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
    When I submit a 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-invalid' details to the CRI stub
    Then I get a 'pyi-no-match' page response

  Scenario: TICF error scenario - PYI_ANOTHER_WAY
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
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
    When I submit a 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'pyi-post-office' page response
    When I submit a 'end' event
    Then I get a 'pyi-another-way' page response

  Scenario: TICF error scenario - PYI_TECHNICAL
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
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
    When I submit an 'f2f' event
    Then I get a 'f2f' CRI response
    When I get an 'temporarily_unavailable' OAuth error from the CRI stub
    Then I get a 'pyi-technical' page response

  Scenario: PYI_ESCAPE
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'page-ipv-identity-postoffice-start' page response
    When I submit an 'end' event
    Then I get a 'pyi-escape' page response

  Scenario: PYI_ESCAPE_M2B
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
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
