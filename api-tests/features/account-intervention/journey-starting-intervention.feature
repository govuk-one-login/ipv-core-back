@Build
Feature: First Account Intervention call

  Scenario Outline: Not allowed <intervention> intervention on start of identity proving journey
    Given I activate the 'accountInterventions' feature set
    And The AIS stub will return an '<response>' result
    When I start a new 'medium-confidence' journey
    Then I get an OAuth response with error code 'session_invalidated'

    Examples:
      | intervention                        | response                                            |
      | Blocked                             | AIS_ACCOUNT_BLOCKED                                 |
      | Suspended                           | AIS_ACCOUNT_SUSPENDED                               |
      | Password reset                      | AIS_FORCED_USER_PASSWORD_RESET                      |
      | Password reset and reprove identity | AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY  |

  Scenario Outline: Allowed <intervention> intervention on start of identity proving journey
    Given I activate the 'accountInterventions' feature set
    And The AIS stub will return an '<response>' result
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response

#    Reprove identity is handled in separate file
    Examples:
      | intervention                        | response                                            |
      | No intervention                     | AIS_NO_INTERVENTION                                 |
      | Unsuspended                         | AIS_ACCOUNT_UNSUSPENDED                             |
      | Unblocked                           | AIS_ACCOUNT_UNBLOCKED                               |
