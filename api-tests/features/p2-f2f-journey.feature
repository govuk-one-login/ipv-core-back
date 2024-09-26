@Build
Feature: P2 F2F journey

  Rule: Pending F2F journey
    Background: User has pending f2f verification
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
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get a 'page-face-to-face-handoff' page response

    Scenario: Pending F2F request
      # Initial journey
      Given I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-pending' page response

    Scenario: Pending F2F request delete identity
      # Initial journey
      Given I start a new 'medium-confidence' journey with feature set 'pendingF2FResetEnabled'
      Then I get a 'page-ipv-pending' page response with context 'f2f-delete-details'
      When I submit a 'next' event
      Then I get a 'pyi-f2f-delete-details' page response
      When I submit a 'next' event
      Then I get a 'pyi-confirm-delete-details' page response with context 'f2f'
      When I submit a 'next' event
      Then I get a 'pyi-details-deleted' page response with context 'f2f'
      And an 'IPV_F2F_USER_CANCEL_START' audit event was recorded [local only]

    Scenario: Pending F2F request continue without delete identity
      # Initial journey
      Given I start a new 'medium-confidence' journey with feature set 'pendingF2FResetEnabled'
      Then I get a 'page-ipv-pending' page response with context 'f2f-delete-details'
      When I submit a 'next' event
      Then I get a 'pyi-f2f-delete-details' page response
      When I submit a 'end' event
      Then I get a 'page-ipv-pending' page response with context 'f2f-delete-details'
      When I submit a 'next' event
      Then I get a 'pyi-f2f-delete-details' page response
      When I submit a 'next' event
      Then I get a 'pyi-confirm-delete-details' page response with context 'f2f'
      When I submit a 'end' event
      Then I get a 'page-ipv-pending' page response with context 'f2f-delete-details'

  Rule: Successful F2F journeys
    Scenario Outline: Successful P2 identity via F2F using <doc>
      # Initial journey
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
      When I submit '<details>' details to the async CRI stub
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And an 'IPV_IDENTITY_ISSUED' audit event was recorded [local only]

      Examples:
        | doc      | details                      |
        | passport | kenneth-passport-valid       |
        | DL       | kenneth-driving-permit-valid |

    Scenario Outline: Successful P2 identity via F2F using <doc> - DCMAW access_denied
      # Initial journey
      Given I start a new 'medium-confidence' journey
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get a 'page-multiple-doc-check' page response
      When I submit a 'end' event
      Then I get a 'pyi-post-office' page response
      When I submit a 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'f2f' CRI response
      When I submit '<details>' details to the async CRI stub
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And an 'IPV_IDENTITY_ISSUED' audit event was recorded [local only]

      Examples:
        | doc      | details                      |
        | passport | kenneth-passport-valid       |
        | DL       | kenneth-driving-permit-valid |

  Rule: Oauth error F2F journeys
    Background: User starts F2F journey
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

    Scenario: Oauth access_denied error F2F
      # Initial journey
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get a 'pyi-another-way' page response

    Scenario: Oauth temporarily_unavailable error F2F
      # Initial journey
      When I get an 'temporarily_unavailable' OAuth error from the CRI stub
      Then I get a 'pyi-technical' page response

    Scenario: Async queue error
      When I get an error from the async CRI stub
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start a new 'medium-confidence' journey and return to a 'pyi-f2f-technical' page response
      When I submit a 'end' event
      Then I get an OAuth response

  Scenario: F2F PYI escpae route
    Given I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'pyi-escape' page response

  Rule: F2F evidence requested strength score
    Background: User has pending F2F verification
      Given I start a new 'medium-confidence' journey
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get a 'page-multiple-doc-check' page response
      When I submit a 'end' event
      Then I get a 'pyi-post-office' page response
      When I submit a 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response

    Scenario: requested strength score three for fraud score 2
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'f2f' CRI response
      When I submit 'kenneth-passport-valid' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'page-face-to-face-handoff' page response

    Scenario: requested strength score four for fraud score 1
      When I submit 'kenneth-score-1' details to the CRI stub
      Then I get a 'f2f' CRI response
      When I submit 'kenneth-passport-valid' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":4} |
      Then I get a 'page-face-to-face-handoff' page response

    Scenario: requested strength score four fraud score 1 and history 0
      When I submit 'kenneth-score-1-history-0' details to the CRI stub
      Then I get a 'f2f' CRI response
      When I submit 'kenneth-passport-valid' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":4} |
      Then I get a 'page-face-to-face-handoff' page response

    Scenario: requested strength score four for fraud score 2 and history 0
      When I submit 'kenneth-score-2-history-0' details to the CRI stub
      Then I get a 'f2f' CRI response
      When I submit 'kenneth-passport-valid' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":4} |
      Then I get a 'page-face-to-face-handoff' page response
