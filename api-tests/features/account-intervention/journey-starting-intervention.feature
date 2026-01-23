@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: First Account Intervention call

  Rule: Compare AIS descriptions
    Background: Enable AIS description checking
      Given I activate the 'disableAisStateCheck' feature set

    Scenario Outline: Not allowed <intervention> intervention on start of identity proving journey
      Given The AIS stub will return an '<response>' result
      When I start a new 'medium-confidence' journey
      Then I get an OAuth response with error code 'session_invalidated'

      Examples:
        | intervention                        | response                                            |
        | Blocked                             | AIS_ACCOUNT_BLOCKED                                 |
        | Suspended                           | AIS_ACCOUNT_SUSPENDED                               |
        | Password reset                      | AIS_FORCED_USER_PASSWORD_RESET                      |
        | Password reset and reprove identity | AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY  |

    Scenario Outline: Allowed <intervention> intervention on start of identity proving journey
      Given The AIS stub will return an '<response>' result
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response

  #    Reprove identity is handled in separate file
      Examples:
        | intervention                        | response                                            |
        | No intervention                     | AIS_NO_INTERVENTION                                 |
        | Unsuspended                         | AIS_ACCOUNT_UNSUSPENDED                             |
        | Unblocked                           | AIS_ACCOUNT_UNBLOCKED                               |

  Rule: Compare AIS states
    Background: Enable AIS state checking
      Given I activate the 'aisStateCheck' feature set

    Scenario Outline: Not allowed <intervention> intervention on start of identity proving journey
      Given The AIS stub will return an '<response>' result
      When I start a new 'medium-confidence' journey
      Then I get an OAuth response with error code 'session_invalidated'

      Examples:
        | intervention                        | response                                            |
        | Blocked                             | AIS_ACCOUNT_BLOCKED                                 |
        | Suspended                           | AIS_ACCOUNT_SUSPENDED                               |
        | Password reset                      | AIS_FORCED_USER_PASSWORD_RESET                      |
        | Password reset and reprove identity | AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY  |

    Scenario Outline: Allowed <intervention> intervention on start of identity proving journey
      Given The AIS stub will return an '<response>' result
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response

  #    Reprove identity is handled in separate file
      Examples:
        | intervention                        | response                                |
        | No intervention                     | AIS_NO_INTERVENTION                     |
        | Unsuspended                         | AIS_ACCOUNT_UNSUSPENDED                 |
        | Unblocked                           | AIS_ACCOUNT_UNBLOCKED                   |
        | Password reset cleared              | AIS_PASSWORD_RESET_CLEARED              |
        | Password reset and reverify cleared | AIS_PASSWORD_RESET_AND_REVERIFY_CLEARED |
        | Ewvweification cleared              | AIS_REVERIFY_CLEARED                    |
