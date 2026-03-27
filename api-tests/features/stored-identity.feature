@Build @QualityGateIntegrationTest @QualityGateRegressionTest @dcc
Feature: Stored Identity

  Rule: No existing SI record
    Scenario: Reuse creates new stored identity
      Given the subject already has the following credentials with overridden document expiry date
        | CRI     | scenario                     | documentType  |
        | dcmaw   | kenneth-driving-permit-valid | drivingPermit |
      And the subject already has the following credentials
        | CRI     | scenario                     |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      And I don't have a stored identity in EVCS
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P1' identity
      And I have a stored identity record with a 'P2' max vot

  Rule: Existing SI record is invalidated once update starts
    Background:
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
      And the subject already has the following expired credentials
        | CRI   | scenario        |
        | fraud | kenneth-score-2 |
      And I have an existing stored identity record with a 'P2' vot

    Scenario: Update name invalidates stored identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck' and pageContext
        | Context     | Value            |
        | journeyType | repeatFraudCheck |
      And I have a stored identity record with a 'P2' max vot that is 'invalid'

    Scenario: Update address invalidates stored identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response
      When I submit a 'address-only' event
      Then I get a 'address' CRI response
      And I have a stored identity record with a 'P2' max vot that is 'invalid'

    Scenario: Update name and address invalidates stored identity
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response
      When I submit a 'family-name-and-address' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck' and pageContext
        | Context     | Value            |
        | journeyType | repeatFraudCheck |
      And I have a stored identity record with a 'P2' max vot that is 'invalid'
