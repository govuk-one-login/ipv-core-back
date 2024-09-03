@Build
Feature: Failed TICF requests
  Scenario Outline: TICF Management API request configured for 400 initially and no CI in reuse journey
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | randomUuid                   |
      | statusCode    | <statusCode>                          |
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

    Examples:
      | statusCode |
      | 400        |
      | 500        |