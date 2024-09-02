@Build
Feature: MFA reset journey

  Scenario: MFA reset journey
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |

    # Start MFA Reset journey for existing user
    When I start a new 'reverification' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my MFA reset result
    Then I get a successful MFA reset result
