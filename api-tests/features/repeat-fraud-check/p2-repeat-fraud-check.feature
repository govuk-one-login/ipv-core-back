@Build
Feature: Repeat fraud check journeys

  Background:
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
    And the subject already has the following expired credentials
      | CRI   | scenario        |
      | fraud | kenneth-score-2 |
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response

  Scenario: Fraud 6 Months Expiry + No Update
    # Repeat fraud check with no update
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit expired 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: Fraud 6 Months Expiry + Given Name Update
    # Repeat fraud check with update name
    When I submit a 'given-names-only' event
    Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
    When I submit a 'update-name' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-given-name-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And my identity 'GivenName' is 'Ken'
    And my identity 'FamilyName' is 'Decerqueira'

  Scenario: Fraud 6 Months Expiry + Family Name Update
    # Repeat fraud check with update family name
    When I submit a 'family-name-only' event
    Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
    When I submit a 'update-name' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-family-name-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And my identity 'GivenName' is 'Kenneth'
    And my identity 'FamilyName' is 'Smith'

  Scenario: Fraud 6 Months Expiry + Address Update
    # Repeat fraud check with update address
    When I submit a 'address-only' event
    Then I get a 'address' CRI response
    When I submit 'kenneth-changed' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And my address 'buildingNumber' is '28'
    And my address 'addressLocality' is 'Bristol'

  Scenario: Fraud 6 Months Expiry + Address and Family Name Update
    # Repeat fraud check with update address and family name
    When I submit a 'family-name-and-address' event
    Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
    When I submit a 'update-name' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
    When I submit a 'next' event
    Then I get a 'address' CRI response
    When I submit 'kenneth-changed' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-family-name-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And my identity 'FamilyName' is 'Smith'
    And my address 'addressLocality' is 'Bristol'

  Scenario: Fraud 6 Months Expiry + Address and Given Name Update
    # Repeat fraud check with update address and given name
    When I submit a 'given-names-and-address' event
    Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
    When I submit a 'update-name' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
    When I submit a 'next' event
    Then I get a 'address' CRI response
    When I submit 'kenneth-changed' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-given-name-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And my identity 'GivenName' is 'Ken'
    And my address 'streetName' is 'King Road'

  Scenario: Unsupported Changes
    # Repeat fraud check with various unsupported events and back navigation
    When I submit a 'dob' event
    Then I get a 'update-name-date-birth' page response with context 'repeatFraudCheck'
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-dob' event
    Then I get a 'update-name-date-birth' page response with context 'repeatFraudCheck'
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'dob-family' event
    Then I get a 'update-name-date-birth' page response with context 'repeatFraudCheck'
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'dob-given' event
    Then I get a 'update-name-date-birth' page response with context 'repeatFraudCheck'
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'family-given' event
    Then I get a 'update-name-date-birth' page response with context 'repeatFraudCheck'
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-family-given' event
    Then I get a 'update-name-date-birth' page response with context 'repeatFraudCheck'
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-dob-family-given' event
    Then I get a 'update-name-date-birth' page response with context 'repeatFraudCheck'
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-dob-family' event
    Then I get a 'update-name-date-birth' page response with context 'repeatFraudCheck'
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-dob-given' event
    Then I get a 'update-name-date-birth' page response with context 'repeatFraudCheck'
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-family-given' event
    Then I get a 'update-name-date-birth' page response with context 'repeatFraudCheck'
