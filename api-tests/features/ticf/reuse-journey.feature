Feature: TICF reuse journey
  Background: The user already has credentials
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |

  Scenario: TICF request returns no CIs
    Given TICF CRI will respond with default parameters
      | | |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And my identity includes a 'TICF' credential
    And the TICF VC has default properties

  Scenario: TICF request returns a CI
    Given TICF CRI will respond with default parameters
      | cis | BREACHING   |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
    And my identity includes a 'TICF' credential
    And the TICF VC has default properties with 'BREACHING' CI
