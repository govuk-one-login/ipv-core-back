@Build
Feature: Fail open scenarios

  Scenario Outline: Journey with AIS failures but no interventions succeeds
    Given I activate the 'accountInterventions,disableStrategicApp' feature set
    When The AIS stub will return an '<first_ais_response>' result
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When The AIS stub will return an '<second_ais_response>' result
    And I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response

    Examples:
      | first_ais_response  | second_ais_response |
      | ERROR               | AIS_NO_INTERVENTION |
      | AIS_NO_INTERVENTION | ERROR               |
      | ERROR               | ERROR               |

  Scenario Outline: Journey with AIS failure and <intervention> intervention fails
    Given I activate the 'accountInterventions,disableStrategicApp' feature set
    When The AIS stub will return an '<first_ais_response>' result
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When The AIS stub will return an '<second_ais_response>' result
    And I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get an OAuth response with error code 'session_invalidated'
    And I don't have a stored identity in EVCS

    Examples:
      | intervention           | first_ais_response  | second_ais_response             |
      | initial blocked        | AIS_ACCOUNT_BLOCKED | ERROR                           |
      | final blocked          | ERROR               | AIS_ACCOUNT_BLOCKED             |
      | final reprove identity | ERROR               | AIS_FORCED_USER_IDENTITY_VERIFY |


  Scenario: Reprove identity journey with AIS failure succeeds
    Given I activate the 'accountInterventions,disableStrategicApp' feature set
    And the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
    When I start a new 'medium-confidence' journey
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When The AIS stub will return an 'ERROR' result
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response
