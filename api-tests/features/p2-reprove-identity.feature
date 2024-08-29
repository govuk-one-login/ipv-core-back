@Build
Feature: Reprove Identity Journey

    Scenario: User needs to reprove their identity
        Given the subject already has the following credentials
            | CRI     | scenario                     |
            | dcmaw   | kenneth-driving-permit-valid |
            | address | kenneth-current              |
            | fraud   | kenneth-score-2              |
        When I start a new 'medium-confidence' journey with reprove identity
        Then I get a 'reprove-identity-start' page response
        When I submit a 'next' event
        Then I get a 'page-ipv-identity-document-start' page response
