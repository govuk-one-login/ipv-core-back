@Build
Feature: Account Deletion

  Scenario: Successfully delete an account
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    When I start a new 'medium-confidence' journey with feature set 'deleteDetailsTestJourney'
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get a 'pyi-new-details' page response
    When I submit a 'next' event
    Then I get a 'pyi-confirm-delete-details' page response
    When I submit a 'next' event
    Then I get a 'pyi-details-deleted' page response
    When I submit a 'next' event
    Then I get a 'page-ipv-identity-document-start' page response

    Scenario: Choose not to delete account
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      When I start a new 'medium-confidence' journey with feature set 'deleteDetailsTestJourney'
      Then I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get a 'pyi-new-details' page response
      When I submit a 'end' event
      Then I get a 'page-ipv-reuse' page response

  Scenario: Dropout of account deletion
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    When I start a new 'medium-confidence' journey with feature set 'deleteDetailsTestJourney'
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get a 'pyi-new-details' page response
    When I submit a 'next' event
    Then I get a 'pyi-confirm-delete-details' page response
    When I submit a 'end' event
    Then I get a 'page-ipv-reuse' page response
