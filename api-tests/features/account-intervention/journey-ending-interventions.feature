@Build
Feature: Journey ending interventions

  Scenario Outline: <intervention> intervention at <when> of identity proving journey
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
    And TICF CRI will respond with default parameters and
      | interventionCode | <ticf_intervention_code> |
    And I submit 'kenneth-score-2' details to the CRI stub
    Then I get an OAuth response with error code 'session_invalidated'

    Examples:
      | intervention                        | when  | first_ais_response             | second_ais_response                                | ticf_intervention_code |
      | Blocked                             | start | AIS_ACCOUNT_BLOCKED            | AIS_NO_INTERVENTION                                | 00                     |
      | Suspended                           | start | AIS_ACCOUNT_SUSPENDED          | AIS_NO_INTERVENTION                                | 00                     |
      | Password reset                      | start | AIS_FORCED_USER_PASSWORD_RESET | AIS_NO_INTERVENTION                                | 00                     |
      | Blocked                             | end   | AIS_NO_INTERVENTION            | AIS_ACCOUNT_BLOCKED                                | 00                     |
      | Suspended                           | end   | AIS_NO_INTERVENTION            | AIS_ACCOUNT_SUSPENDED                              | 00                     |
      | Password reset                      | end   | AIS_NO_INTERVENTION            | AIS_FORCED_USER_PASSWORD_RESET                     | 00                     |
      | Reprove identity                    | end   | AIS_NO_INTERVENTION            | AIS_FORCED_USER_IDENTITY_VERIFY                    | 00                     |
      | Password reset and reprove identity | end   | AIS_NO_INTERVENTION            | AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY | 00                     |
      | Blocked                             | end   | AIS_NO_INTERVENTION            | AIS_NO_INTERVENTION                                | 03                     |
      | Suspended                           | end   | AIS_NO_INTERVENTION            | AIS_NO_INTERVENTION                                | 01                     |
      | Password reset                      | end   | AIS_NO_INTERVENTION            | AIS_NO_INTERVENTION                                | 04                     |
      | Reprove identity                    | end   | AIS_NO_INTERVENTION            | AIS_NO_INTERVENTION                                | 05                     |
      | Password reset and reprove identity | end   | AIS_NO_INTERVENTION            | AIS_NO_INTERVENTION                                | 06                     |

  Scenario Outline: <intervention> intervention at <when> of reprove identity journey
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
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get an OAuth response with error code 'session_invalidated'

    Examples:
      | intervention                        | when  | first_ais_response                                 | second_ais_response                                |
      | Password reset and reprove identity | start | AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY | AIS_NO_INTERVENTION                                |
      | Blocked                             | end   | AIS_FORCED_USER_IDENTITY_VERIFY                    | AIS_ACCOUNT_BLOCKED                                |
      | Suspended                           | end   | AIS_FORCED_USER_IDENTITY_VERIFY                    | AIS_ACCOUNT_SUSPENDED                              |
      | Password reset                      | end   | AIS_FORCED_USER_IDENTITY_VERIFY                    | AIS_FORCED_USER_PASSWORD_RESET                     |
      | Password reset and reprove identity | end   | AIS_FORCED_USER_IDENTITY_VERIFY                    | AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY |

  Scenario Outline: <intervention> intervention <when> of update identity journey
    Given I activate the 'accountInterventions' feature set
    And the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an '<first_ais_response>' result
    When I start a new 'medium-confidence' journey with AIS stub response of '<second_ais_response>'
    Then I get an OAuth response with error code 'session_invalidated'

    Examples:
      | intervention | when                              | first_ais_response    | second_ais_response |
      | Suspended    | at start                          | AIS_ACCOUNT_SUSPENDED | AIS_NO_INTERVENTION |
      | Blocked      | after initial journey selection   | AIS_NO_INTERVENTION   | AIS_ACCOUNT_BLOCKED |

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
    When I submit 'kenneth-score-2' details to the CRI stub
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
    And I submit 'kenneth-score-2' details to the CRI stub
    Then I get an OAuth response with error code 'session_invalidated'
