@Build
Feature: Failed TICF requests
  Scenario Outline: TICF CRI returns a <statusCode> during identity proving and no CI in reuse
    Given TICF CRI will respond with default parameters and
      | statusCode    | <statusCode>                 |
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
    Then I get a 'P2' identity
    And my identity does not include a 'TICF' credential

    Given TICF CRI will respond with default parameters
      | statusCode    | 200                 |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-reuse' page response
    And my proven user details match
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And my identity includes a 'TICF' credential
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |

    Examples:
      | statusCode |
      | 400        |
      | 500        |
