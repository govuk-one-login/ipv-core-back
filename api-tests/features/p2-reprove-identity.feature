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

    Scenario: User needs to reprove their identity with F2F pending
        Given I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-identity-document-start' page response
        When I submit an 'end' event
        Then I get a 'page-ipv-identity-postoffice-start' page response
        When I submit a 'next' event
        Then I get a 'claimedIdentity' CRI response
        When I submit 'kenneth-current' details to the CRI stub
        Then I get an 'address' CRI response
        When I submit 'kenneth-current' details to the CRI stub
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-score-2' details to the CRI stub
        Then I get a 'f2f' CRI response
        When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
            | Attribute          | Values                                          |
            | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
        Then I get a 'page-face-to-face-handoff' page response
        When I start a new 'medium-confidence' journey with reprove identity
        Then I get a 'reprove-identity-start' page response
        When I submit a 'next' event
        Then I get a 'page-ipv-identity-document-start' page response