Feature: Update details

Background:
    Given I start a new 'medium-confidence' journey
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
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    When I return using my identity
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'update-details' event
    Then I get a 'update-details' page response

@Build
Scenario: Given Name Change
    When I submit a 'given-names-only' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-given-name-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And My identity 'GivenName' is 'Ken'

@Build
Scenario: Family Name Change
    When I submit a 'family-name-only' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-family-name-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And My identity 'FamilyName' is 'Smith'

@Build
Scenario: Address Change
    When I submit a 'address-only' event
    Then I get a 'address' CRI response
    When I submit 'kenneth-changed' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And My identity 'buildingNumber' is '28'

@Build
Scenario: Address and Family Name Change
    When I submit a 'family-name-and-address' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
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
    And My identity 'FamilyName' is 'Smith'
    And My identity 'buildingNumber' is '28'

@Build
Scenario: Address and Given Name Change
    When I submit a 'given-names-and-address' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
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
    And My identity 'GivenName' is 'Ken'
    And My identity 'buildingNumber' is '28'

@Build
Scenario: Date of Birth Change
    When I submit a 'dob' event
    Then I get a 'update-name-date-birth' page response

@Build
Scenario: Address and Date of Birth Change
    When I submit a 'address-dob' event
    Then I get a 'update-name-date-birth' page response

@Build
Scenario: Date of Birth Change and Family Name Change
    When I submit a 'dob-family' event
    Then I get a 'update-name-date-birth' page response

@Build
Scenario: Date of Birth Change and Given Name Change
    When I submit a 'dob-given' event
    Then I get a 'update-name-date-birth' page response

@Build
Scenario: Family Name and Given Name Change
    When I submit a 'family-given' event
    Then I get a 'update-name-date-birth' page response

@Build
Scenario: Address, Family Name and Given Name Change
    When I submit a 'address-family-given' event
    Then I get a 'update-name-date-birth' page response

@Build
Scenario: Address, Date of Birth, Family Name and Given Name Change
    When I submit a 'address-dob-family-given' event
    Then I get a 'update-name-date-birth' page response

@Build
Scenario: Address, Date of Birth and Family Name Change
    When I submit a 'address-dob-family' event
    Then I get a 'update-name-date-birth' page response

@Build
Scenario: Address, Date of Birth and Given Name Change
    When I submit a 'address-dob-given' event
    Then I get a 'update-name-date-birth' page response

@Build
Scenario: Date of Birth, Family Name and Given Name Change
    When I submit a 'address-family-given' event
    Then I get a 'update-name-date-birth' page response
