Feature: CIMIT - Enhanced verification

  Background:
    # Navigate to KBV CRI and apply NEEDS-ENHANCED-VERIFICATION CI
    Given I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-multiple-doc-check' page response
    When I submit a 'drivingLicence' event
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-needs-enhanced-verification' details to the CRI stub
    Then I get a 'pyi-suggest-other-options' page response

  Scenario: CIMIT - Enhanced verification mitigation via DCMAW (same session mitigation)
    When I submit a 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |

  Scenario: CIMIT - Enhanced verification mitigation via DCMAW (separate session mitigation)
    # Start new session as the same user
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
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
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |

  Scenario: CIMIT - Enhanced verification mitigation via F2F
    When I submit a 'f2f' event
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |
