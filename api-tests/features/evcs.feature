@RealEvcs # Temporary test to be run in whitelisted VPC
Feature: P2 Reuse journey - Real EVCS

  Scenario: Reuse journey - user has to paginate VCs
    Given the subject already has the following credentials
      | CRI        | scenario               | numCredentials |
      | dcmaw      | kenneth-passport-valid | 100            |
      | address    | kenneth-current        | 1              |
      | fraud      | kenneth-score-2        | 1              |

    When I start a new 'high-medium-confidence' journey
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P3' identity
    And I have 102 VCs