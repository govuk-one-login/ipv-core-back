@Build
Feature: P2 App journey

  Background:
    Given I start a new 'medium-confidence' journey
    And I activate the 'internationalAddress' feature sets
    And I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit an 'international' event
    Then I get a 'dcmaw' CRI response

  Scenario: Successful P2 identity via DCMAW using passport
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-changed' details with attributes to the CRI stub
      | Attribute | Values               |
      | context   | "international_user" |
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And an 'IPV_IDENTITY_ISSUED' audit event was recorded [local only]
