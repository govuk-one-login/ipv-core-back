@Build
Feature: P1 app journey

  Scenario: P1 App Journey
    Given I activate the 'p1Journeys,storedIdentityService' feature sets
    When I start a new 'low-confidence' journey
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
    When I submit 'kenneth-score-1' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P1' identity
    And I have a 'GPG45' stored identity record type with a 'P2' vot

  Scenario Outline: <error> from DCMAW
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an '<error>' OAuth error
    Then I get a '<expected_page>' page response with context '<context>'

    Examples:
      | error                     | expected_page           | context |
      | server_error              | pyi-technical           | null    |
      | temporarily_unavailable   | page-multiple-doc-check | nino    |
      | invalid_request           | pyi-no-match            | null    |
      | unauthorized_client       | pyi-technical           | null    |
      | unsupported_response_type | pyi-technical           | null    |
      | invalid_scope             | pyi-technical           | null    |
