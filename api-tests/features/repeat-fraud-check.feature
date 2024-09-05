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
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |

  Scenario: Fraud 6 Months Expiry + Given Name Update
    # Repeat fraud check with update given name
    When I submit a 'given-names-only' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-first-name-only-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-first-name-only-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And my identity 'GivenName' is 'Michael'
    And my identity 'FamilyName' is 'Decerqueira'
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |

  Scenario: Fraud 6 Months Expiry + Family Name Update
    # Repeat fraud check with update family name
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
    And my identity 'GivenName' is 'Kenneth'
    And my identity 'FamilyName' is 'Smith'
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |

  Scenario: Fraud 6 Months Expiry + Address Update
    # Repeat fraud check with update address
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
    And my address 'buildingNumber' is '28'
    And my address 'addressLocality' is 'Bristol'
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |

  Scenario: Fraud 6 Months Expiry + Address and Family Name Update
    # Repeat fraud check with update address and family name
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
    And my identity 'FamilyName' is 'Smith'
    And my address 'addressLocality' is 'Bristol'
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |

  Scenario: Fraud 6 Months Expiry + Address and Given Name Update
    # Repeat fraud check with update address and given name
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
    And my identity 'GivenName' is 'Ken'
    And my address 'streetName' is 'King Road'
    And the TICF VC has properties
      | cis  |                              |
      | type | RiskAssessment               |

  Scenario: Unsupported Changes
    # Repeat fraud check with various unsupported events and back navigation
    When I submit a 'dob' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-dob' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'dob-family' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'dob-given' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'family-given' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-family-given' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-dob-family-given' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-dob-family' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-dob-given' event
    Then I get a 'update-name-date-birth' page response
    When I submit a 'back' event
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-family-given' event
    Then I get a 'update-name-date-birth' page response

  Scenario: Fraud 6 Months Expiry + Given Name Update Failure
    # Repeat fraud check with update given name failure
    When I submit a 'given-names-only' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-family-name-score-2' details to the CRI stub
    Then I get a 'sorry-could-not-confirm-details' page response
