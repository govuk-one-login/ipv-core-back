@Build
Feature: Update details failures

    Background:
        Given the subject already has the following credentials
            | CRI     | scenario                     |
            | dcmaw   | kenneth-driving-permit-valid |
            | address | kenneth-current              |
            | fraud   | kenneth-score-2              |
        When I start a new 'medium-confidence' journey with feature set 'updateDetailsAccountDeletion'
        Then I get a 'page-ipv-reuse' page response
        When I submit a 'update-details' event
        Then I get a 'update-details' page response

    @FastFollow
    Scenario: Given Name change failed in DCMAW auth error
        When I submit a 'given-names-only' event
        Then I get a 'page-update-name' page response
        When I submit a 'update-name' event
        Then I get a 'dcmaw' CRI response
        When I get an 'access_denied' OAuth error from the CRI stub
        Then I get a 'update-details-failed' page response
        When I submit a 'continue' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I get a 'P0' identity
        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
