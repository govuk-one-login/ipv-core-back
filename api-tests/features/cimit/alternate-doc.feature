Feature: CIMIT - Alternate doc

  Scenario Outline: CIMIT - Alternate doc mitigation via passport or DL
    Given I start a new 'medium-confidence' journey
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
