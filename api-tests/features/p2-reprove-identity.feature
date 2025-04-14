@Build
Feature: Reprove Identity Journey
    Scenario: User reproves identity
        Given the subject already has the following credentials
            | CRI     | scenario                     |
            | dcmaw   | kenneth-driving-permit-valid |
            | address | kenneth-current              |
            | fraud   | kenneth-score-2              |
        When I start a new 'medium-confidence' journey with reprove identity
        Then I get a 'reprove-identity-start' page response
        When I submit a 'next' event
        Then I get a 'live-in-uk' page response
        When I submit a 'uk' event
        Then I get a 'page-ipv-identity-document-start' page response
        When I submit an 'appTriage' event
        Then I get a 'dcmaw' CRI response
        When I submit 'kenneth-passport-valid' details to the CRI stub
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

    Scenario: User reproves with F2F
        Given the subject already has the following credentials
            | CRI     | scenario                     |
            | dcmaw   | kenneth-driving-permit-valid |
            | address | kenneth-current              |
            | fraud   | kenneth-score-2              |
        When I start a new 'medium-confidence' journey with reprove identity
        Then I get a 'reprove-identity-start' page response
        When I submit a 'next' event
        Then I get a 'live-in-uk' page response
        When I submit a 'uk' event
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
        When I submit 'kenneth-driving-permit-valid' details with attributes to the async CRI stub
            | Attribute          | Values                                          |
            | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
        Then I get a 'page-face-to-face-handoff' page response

        # Return journey after popping out to the Post Office
        When I start a new 'medium-confidence' journey with reprove identity and return to a 'page-ipv-reuse' page response
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I get a 'P2' identity

    Scenario: User needs to reprove their identity with F2F pending
        Given I start a new 'medium-confidence' journey
        Then I get a 'live-in-uk' page response
        When I submit a 'uk' event
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
        When I submit 'kenneth-driving-permit-valid' details with attributes to the async CRI stub
            | Attribute          | Values                                          |
            | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
        Then I get a 'page-face-to-face-handoff' page response

        # Users been to the Post Office but sadly now has an account intervention
        When I start a new 'medium-confidence' journey with reprove identity
        Then I get a 'reprove-identity-start' page response
        When I submit a 'next' event
        Then I get a 'live-in-uk' page response

    Rule: F2F journeys are subject to COI checks
        Background:
            Given the subject already has the following credentials
                | CRI     | scenario                     |
                | dcmaw   | kenneth-driving-permit-valid |
                | address | kenneth-current              |
                | fraud   | kenneth-score-2              |
            When I start a new 'medium-confidence' journey with reprove identity
            Then I get a 'reprove-identity-start' page response
            When I submit a 'next' event
            Then I get a 'live-in-uk' page response
            When I submit a 'uk' event
            Then I get a 'page-ipv-identity-document-start' page response
            When I submit an 'end' event
            Then I get a 'page-ipv-identity-postoffice-start' page response
            When I submit a 'next' event
            Then I get a 'claimedIdentity' CRI response

        Scenario: Reproving with F2F journey with same identity passes COI check
            When I submit 'kenneth-current' details to the CRI stub
            Then I get an 'address' CRI response
            When I submit 'kenneth-current' details to the CRI stub
            Then I get a 'fraud' CRI response
            When I submit 'kenneth-score-2' details to the CRI stub
            Then I get a 'f2f' CRI response
            When I submit 'kenneth-driving-permit-valid' details with attributes to the async CRI stub
                | Attribute          | Values                                          |
                | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
            Then I get a 'page-face-to-face-handoff' page response

            # Return journey after popping out to the Post Office
            When I start a new 'medium-confidence' journey with reprove identity and return to a 'page-ipv-reuse' page response
            When I submit a 'next' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P2' identity

        Scenario: Reproving with F2F journey with different identity fails COI check
            When I submit 'lora' details to the CRI stub
            Then I get an 'address' CRI response
            When I submit 'lora-current' details to the CRI stub
            Then I get a 'fraud' CRI response
            When I submit 'lora-score-2' details to the CRI stub
            Then I get a 'pyi-no-match' page response
            When I submit a 'next' event
            Then I get an OAuth response
            When I use the OAuth response to get my identity
            Then I get a 'P0' identity
