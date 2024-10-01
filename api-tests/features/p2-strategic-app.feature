@Build
Feature: M2B Strategic App Journeys

  Scenario: MAM journey declared iphone
    Given I start a new 'medium-confidence' journey with feature set 'strategicApp'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'

  Scenario: MAM journey detected iphone
    Given I start a new 'medium-confidence' journey with feature set 'strategicApp'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriageIphone' event
    Then I get a 'pyi-triage-mobile-confirm' page response
    When I submit an 'next' event
    Then I get a 'pyi-triage-mobile-download-app' page response

  Scenario: MAM journey declared android
    Given I start a new 'medium-confidence' journey with feature set 'strategicApp'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response
    When I submit an 'android' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'android'

  Scenario: MAM journey detected android
    Given I start a new 'medium-confidence' journey with feature set 'strategicApp'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriageAndroid' event
    Then I get a 'pyi-triage-mobile-confirm' page response
    When I submit an 'next' event
    Then I get a 'pyi-triage-mobile-download-app' page response

  Scenario: MAM journey no compatible smartphone
    Given I start a new 'medium-confidence' journey with feature set 'strategicApp'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response
    When I submit an 'end' event
    Then I get a 'page-multiple-doc-check' page response

  Scenario: DAD journey iphone
    Given I start a new 'medium-confidence' journey with feature set 'strategicApp'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context 'iphone'

  Scenario: DAD journey android
    Given I start a new 'medium-confidence' journey with feature set 'strategicApp'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response
    When I submit an 'android' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context 'android'

  Scenario: DAD journey no compatible smartphone
    Given I start a new 'medium-confidence' journey with feature set 'strategicApp'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response
    When I submit an 'end' event
    Then I get a 'page-multiple-doc-check' page response

  Scenario: Strategic app no photo ID goes to F2F
    Given I start a new 'medium-confidence' journey with feature set 'strategicApp'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'page-ipv-identity-postoffice-start' page response
