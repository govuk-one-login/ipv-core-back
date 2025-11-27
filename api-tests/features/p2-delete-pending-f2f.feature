@Build
Feature: P2 delete pending F2F journey
  Background: User has pending f2f verification
    Given I activate the 'pendingF2FResetEnabled' feature set
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
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
    Then I get a 'page-face-to-face-handoff' page response

  Scenario: Pending F2F request delete identity
    # Return journey
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-pending' page response with context 'f2f-delete-details'
    When I submit a 'next' event
    Then I get a 'pyi-f2f-delete-details' page response
    When I submit a 'next' event
    Then I get a 'pyi-confirm-delete-details' page response
    When I submit a 'next' event
    Then I get a 'pyi-details-deleted' page response with context 'f2f'

  Scenario: Pending F2F request continue without delete identity
    # Return journey
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-pending' page response with context 'f2f-delete-details'
    When I submit a 'next' event
    Then I get a 'pyi-f2f-delete-details' page response
    When I submit a 'end' event
    Then I get a 'page-ipv-pending' page response with context 'f2f-delete-details'
    When I submit a 'next' event
    Then I get a 'pyi-f2f-delete-details' page response
    When I submit a 'next' event
    Then I get a 'pyi-confirm-delete-details' page response
    When I submit a 'end' event
    Then I get a 'page-ipv-pending' page response with context 'f2f-delete-details'
