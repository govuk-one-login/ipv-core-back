@Build
Feature: Journey ending interventions

  Scenario Outline: <intervention> intervention at of identity proving journey
    Given I activate the 'accountInterventions,disableStrategicApp' feature set
    And The AIS stub will return an '<first_ais_response>' result
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
      | intervention                        | first_ais_response             | second_ais_response                                |
      | Blocked                             | AIS_NO_INTERVENTION            | AIS_ACCOUNT_BLOCKED                                |
      | Suspended                           | AIS_NO_INTERVENTION            | AIS_ACCOUNT_SUSPENDED                              |
      | Password reset                      | AIS_NO_INTERVENTION            | AIS_FORCED_USER_PASSWORD_RESET                     |
      | Reprove identity                    | AIS_NO_INTERVENTION            | AIS_FORCED_USER_IDENTITY_VERIFY                    |
      | Password reset and reprove identity | AIS_NO_INTERVENTION            | AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY |

  Scenario Outline: TICF <intervention> result during identity proving journey
    Given I activate the 'accountInterventions,disableStrategicApp' feature set
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
    When TICF CRI will respond with default parameters and
      | interventionCode | <ticf_intervention_code> |
    And I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get an OAuth response with error code 'session_invalidated'
    And I don't have a stored identity in EVCS

    Examples:
      | intervention                        | ticf_intervention_code |
      | Blocked                             | 03                     |
      | Suspended                           | 01                     |
      | Password reset                      | 04                     |
      | Reprove identity                    | 05                     |
      | Password reset and reprove identity | 06                     |

  Scenario Outline: <intervention> intervention at of reprove identity journey
    Given I activate the 'accountInterventions,disableStrategicApp' feature set
    And the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an '<first_ais_response>' result
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
    When The AIS stub will return an '<second_ais_response>' result
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get an OAuth response with error code 'session_invalidated'
    And I don't have a stored identity in EVCS

    Examples:
      | intervention                        | first_ais_response                                 | second_ais_response                                |
      | Blocked                             | AIS_FORCED_USER_IDENTITY_VERIFY                    | AIS_ACCOUNT_BLOCKED                                |
      | Suspended                           | AIS_FORCED_USER_IDENTITY_VERIFY                    | AIS_ACCOUNT_SUSPENDED                              |
      | Password reset                      | AIS_FORCED_USER_IDENTITY_VERIFY                    | AIS_FORCED_USER_PASSWORD_RESET                     |
      | Password reset and reprove identity | AIS_FORCED_USER_IDENTITY_VERIFY                    | AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY |

  Scenario: <intervention> intervention of update identity journey
    Given I activate the 'accountInterventions' feature set
    And the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an 'AIS_NO_INTERVENTION' result
    When I start a new 'medium-confidence' journey with AIS stub response of 'AIS_ACCOUNT_BLOCKED'
    Then I get an OAuth response with error code 'session_invalidated'

  Scenario: Blocked intervention at end of update identity journey
    Given I activate the 'accountInterventions' feature set
    And the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an 'AIS_NO_INTERVENTION' result
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'update-details' event
    Then I get a 'update-details' page response
    When I submit a 'address-only' event
    Then I get a 'address' CRI response
    When I submit 'kenneth-changed' details with attributes to the CRI stub
      | Attribute | Values               |
      | context   | "international_user" |
    Then I get a 'fraud' CRI response
    When The AIS stub will return an 'AIS_ACCOUNT_BLOCKED' result
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get an OAuth response with error code 'session_invalidated'

  Scenario: Blocked intervention at end of initial F2F journey
    Given I activate the 'accountInterventions' feature set
    And The AIS stub will return an 'AIS_NO_INTERVENTION' result
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'page-ipv-identity-postoffice-start' page response
    When I submit a 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When The AIS stub will return an 'AIS_ACCOUNT_BLOCKED' result
    And I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get an OAuth response with error code 'session_invalidated'
    And I don't have a stored identity in EVCS
