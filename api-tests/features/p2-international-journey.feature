@Build
Feature: P2 App journey

  Background:
    Given I start a new 'medium-confidence' journey
    And I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response

  Scenario: User resides in the UK and navigates to the start page
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response

  Scenario: International address user starting journey sends an audit event
    When I submit a 'international' event
    Then I get a 'non-uk-app-intro' page response
    When I submit a 'useApp' event
    Then I get a 'dcmaw' CRI response

  Scenario: International address user sends a next event on exit page from DCMAW
    When I submit a 'international' event
    Then I get a 'non-uk-app-intro' page response
    When I submit a 'useApp' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'non-uk-no-app' page response
    When I submit a 'next' event
    Then I get a 'dcmaw' CRI response

  Scenario: International address user sends an end event on exit page from DCMAW
    When I submit a 'international' event
    Then I get a 'non-uk-app-intro' page response
    When I submit a 'useApp' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'non-uk-no-app' page response
    When I submit a 'end' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity

  Scenario: Successful P2 international identity via DCMAW using passport
    When I activate the 'storedIdentityService' feature set
    And I submit an 'international' event
    Then I get a 'non-uk-app-intro' page response
    When I submit a 'useApp' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-changed' details with attributes to the CRI stub
      | Attribute | Values               |
      | context   | "international_user" |
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-no-applicable' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And I have a 'GPG45' stored identity record type with a 'P2' vot

  Scenario: User looks for alternative methods to prove identity without using the app
    When I submit an 'international' event
    Then I get a 'non-uk-app-intro' page response
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
