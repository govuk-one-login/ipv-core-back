@Build
Feature: Repeat fraud check failures

  Background:
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
    And the subject already has the following expired credentials
      | CRI   | scenario        |
      | fraud | kenneth-score-2 |
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'given-names-only' event
    Then I get a 'page-update-name' page response
    When I submit an 'update-name' event
    Then I get a 'dcmaw' CRI response

  @FastFollow
  Scenario: Given name change - DCMAW access denied OAuth error
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get an 'sorry-could-not-confirm-details' page response
    When I submit a 'end' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response

  Scenario: Given name change - breaching CI received from DCMAW
    When I submit 'kenneth-driving-permit-breaching-ci' details to the CRI stub
    Then I get a 'sorry-could-not-confirm-details' page response
    When I submit a 'end' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
    When I start a new 'medium-confidence' journey
    Then I get a 'pyi-no-match' page response

  Scenario: Given name change - zero score in fraud CRI
    When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-given-name-score-0' details to the CRI stub
    Then I get a 'sorry-could-not-confirm-details' page response
    When I submit a 'end' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response

  Scenario: Given name change - breaching CI received from fraud CRI
    When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-breaching-ci' details to the CRI stub
    Then I get a 'sorry-could-not-confirm-details' page response
    When I submit a 'end' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
    When I start a new 'medium-confidence' journey
    Then I get a 'pyi-no-match' page response

  Scenario: Given name change - family name changed
    When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-family-name-score-2' details to the CRI stub
    Then I get a 'sorry-could-not-confirm-details' page response

  Scenario: Given name change - breaching CI received from TICF CRI
    When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-given-name-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    Given TICF CRI will respond with default parameters and
      | cis | BREACHING |
    When I start a new 'medium-confidence' journey
    Then I get a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
    And the TICF VC has properties
      | cis  | BREACHING      |
      | type | RiskAssessment |
