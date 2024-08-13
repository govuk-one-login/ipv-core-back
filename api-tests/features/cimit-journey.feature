Feature: CiMit Journeys

  Rule: CiMit - Enhanced verification route
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

    Scenario:7 CIMIT - Enhanced verification mitigation via DCMAW (same session mitigation)
      When I submit a 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub with 'NEEDS-ENHANCED-VERIFICATION' CI to mitigate
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario:7 CIMIT - Enhanced verification mitigation via DCMAW (separate session mitigation)
      # Start new session as the same user
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub with 'NEEDS-ENHANCED-VERIFICATION' CI to mitigate
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

  Rule: CiMit - Alternate doc mitigation
    Scenario Outline: CiMit - Alternate doc mitigation via passport or DL
      Given I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get a 'page-multiple-doc-check' page response
      When I submit an <initialAlternateCri> event
      Then I get a <initialAlternateCri> CRI response
      When I submit <initialInvalidDoc> details to the CRI stub
      Then I get a <noMatchPage> page response
      When I submit a 'next' event
      Then I get a <mitigatingCri> CRI response
      When I submit <mitigatingDoc> details to the CRI stub with 'NEEDS-ALTERNATE-DOC' CI to mitigate
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
        | initialAlternateCri | initialInvalidDoc | noMatchPage | mitigatingCri | mitigatingDoc |
        | 'drivingLicence'    | 'kenneth-driving-permit-needs-alternate-doc' | 'pyi-driving-licence-no-match-another-way' | 'ukPassport' | 'kenneth-passport-valid' |
        | 'ukPassport'        | 'kenneth-passport-needs-alternate-doc'       | 'pyi-passport-no-match-another-way'        | 'drivingLicence'| 'kenneth-driving-permit-valid' |
