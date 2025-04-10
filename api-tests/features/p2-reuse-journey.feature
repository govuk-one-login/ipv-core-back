@Build
Feature: P2 Reuse journey

  @TrafficGeneration
  Scenario: Successful P2 reuse journey
    # First identity proving journey
    Given I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
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

    # Reuse journey
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-reuse' page response
    And my proven user details match
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: User with M1C is sent on reuse journey when no applicable fraud check
    Given the subject already has the following credentials
      | CRI     | scenario               |
      | dcmaw   | kenneth-passport-valid |
      | address | kenneth-current        |
      | fraud   | kenneth-no-applicable  |

    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-reuse' page response
