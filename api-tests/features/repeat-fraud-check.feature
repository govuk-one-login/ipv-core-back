@Build
Feature: Repeat fraud check journeys

  Background:
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
    When I submit expired 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: Fraud 6 Months Expiry + No Update
    # Repeat fraud check with no update
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit expired 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: Fraud 6 Months Expiry + Name Update
    # Repeat fraud check with update name
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'given-names-only' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-first-name-only-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit expired 'kenneth-changed-first-name-only-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity


  Scenario: Fraud 6 Months Expiry + Name Update Failure
    # Repeat fraud check with update name
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'given-names-only' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit expired 'kenneth-changed-family-name-address-score-2' details to the CRI stub
    Then I get a 'sorry-could-not-confirm-details' page response
