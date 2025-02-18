@Build
@TrafficGeneration
Feature: P2 App journey

  Background:
    Given I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response

  Scenario Outline: Successful P2 identity via DCMAW using <doc>
    When I submit '<details>' details to the CRI stub
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

    Examples:
      | doc      | details                      |
      | passport | kenneth-passport-valid       |
      | BRC      | kenneth-brc-valid            |

  Scenario: Successful P2 identity via DCMAW using kenneth-driving-permit-valid
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

  Scenario: DCMAW returns a 404 from user-info endpoint
    Given the CRI stub returns a 404 from its user-info endpoint
    Then I get a 'page-multiple-doc-check' page response

  Scenario Outline: <error> from DCMAW
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an '<error>' OAuth error
    Then I get a '<expected_page>' page response

    Examples:
      | error                     | expected_page           |
      | server_error              | pyi-technical           |
      | temporarily_unavailable   | page-multiple-doc-check |
      | invalid_request           | pyi-no-match            |
      | unauthorized_client       | pyi-technical           |
      | unsupported_response_type | pyi-technical           |
      | invalid_scope             | pyi-technical           |

  Scenario: Fail DCMAW with no CI
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-fail-no-ci' details to the CRI stub
    Then I get a 'page-multiple-doc-check' page response
