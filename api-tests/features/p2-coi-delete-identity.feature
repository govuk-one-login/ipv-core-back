@Build
Feature: Delete identity

  Background:
    Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
    And I activate the 'updateDetailsAccountDeletion' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'update-details' event
    Then I get a 'update-details' page response

  Scenario: Account deletion update dob
    When I submit a 'dob' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'end' event
    Then I get a 'delete-handover' page response
    When I submit a 'back' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'back' event
    Then I get a 'update-details' page response
    When I submit a 'dob-given' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'end' event
    Then I get a 'delete-handover' page response
    When I submit a 'back' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'back' event
    Then I get a 'update-details' page response
    When I submit a 'dob-family' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'end' event
    Then I get a 'delete-handover' page response
    When I submit a 'back' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'back' event
    Then I get a 'update-details' page response
    When I submit a 'dob-family-given' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'end' event
    Then I get a 'delete-handover' page response
    When I submit a 'back' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'back' event
    Then I get a 'update-details' page response
    When I submit a 'address-dob' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'end' event
    Then I get a 'delete-handover' page response
    When I submit a 'back' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'back' event
    Then I get a 'update-details' page response
    When I submit a 'address-dob-given' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'end' event
    Then I get a 'delete-handover' page response
    When I submit a 'back' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'back' event
    Then I get a 'update-details' page response
    When I submit a 'address-dob-family' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'end' event
    Then I get a 'delete-handover' page response

  Scenario: Account deletion update aborted
    When I submit a 'dob' event
    Then I get a 'update-name-date-birth' page response with context 'reuse'
    When I submit a 'continue' event
    Then I get an OAuth response
    And an 'IPV_USER_DETAILS_UPDATE_ABORTED' audit event was recorded [local only]
