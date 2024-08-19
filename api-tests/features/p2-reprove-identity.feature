@Build
Feature: Reprove Identity Journey

    Scenario: User needs to reprove their identity
        Given I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-identity-document-start' page response
        When I submit an 'appTriage' event
        Then I get a 'dcmaw' CRI response
        When I submit 'kenneth-driving-permit-valid' details to the CRI stub
        Then I get a 'page-dcmaw-success' page response
        When I submit a 'next' event
        Then I get an 'address' CRI response
        When I submit 'kenneth-current' details to the CRI stub
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-score-2' details to the CRI stub
        Then I get a 'page-ipv-success' page response
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my 'identity'
        Then I get a 'P2' identity
        When I start a new 'medium-confidence' journey with reprove identity
        Then I get a 'reprove-identity-start' page response
        When I submit a 'next' event
        Then I get a 'page-ipv-identity-document-start' page response
