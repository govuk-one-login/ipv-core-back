@Build
Feature: Delete identity

  Scenario: Fast Follow COI - Delete
    # Initial journey
    Given TICF CRI will respond with default parameters and
      | responseDelay | 0         |
    When I start a new 'medium-confidence' journey with feature set 'updateDetailsAccountDeletion,ticfCriBeta'
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

    # Run journey again with end
    When I start a new 'medium-confidence' journey with feature set 'updateDetailsAccountDeletion,ticfCriBeta'
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'update-details' event
    Then I get a 'update-details' page response
    When I submit a 'dob-family-given' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'back' event
    Then I get a 'update-details' page response
    When I submit a 'dob' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'back' event
    Then I get a 'update-details' page response
    When I submit a 'dob-given' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'back' event
    Then I get a 'update-details' page response
    When I submit a 'address-dob' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'back' event
    Then I get a 'update-details' page response
    When I submit a 'dob-family-given' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'end' event
    Then I get a 'delete-handover' page response

  Scenario: Fast Follow COI - Continue without delete
    # Initial journey
    Given TICF CRI will respond with default parameters and
      | responseDelay | 0         |
    When I start a new 'medium-confidence' journey with feature set 'updateDetailsAccountDeletion,ticfCriBeta'
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

    # Run journey again with continue
    When I start a new 'medium-confidence' journey with feature set 'updateDetailsAccountDeletion,ticfCriBeta'
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'update-details' event
    Then I get a 'update-details' page response
    When I submit a 'dob' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'continue' event
    Then I get an OAuth response
    And an 'IPV_USER_DETAILS_UPDATE_ABORTED' audit event was recorded [local only]
