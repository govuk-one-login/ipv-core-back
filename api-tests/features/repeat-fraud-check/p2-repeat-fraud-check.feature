@Build @QualityGateIntegrationTest
Feature: Repeat fraud check journeys
  Background: Disable the strategic app
    Given I activate the 'disableStrategicApp' feature set

  Scenario: User is sent on RFC journey to remedy unavailable fraud check
    Given the subject already has the following credentials
      | CRI     | scenario               |
      | dcmaw   | kenneth-passport-valid |
      | address | kenneth-current        |
      | fraud   | kenneth-unavailable    |

    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response

  Rule: Match M1B
    Background: Start journey with expired fraud check
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
      When I submit expired 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
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
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-given-name-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
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
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-changed-family-name-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'

    Scenario: Fraud 6 Months Expiry + Address Update
      # Repeat fraud check with update address
      When I submit a 'address-only' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details with attributes to the CRI stub
        | Attribute | Values               |
        | context   | "international_user" |
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
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
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-changed-family-name-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
      When I submit a 'next' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-family-name-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
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
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
      When I submit a 'next' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details with attributes to the CRI stub
        | Attribute | Values               |
        | context   | "international_user" |
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-given-name-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'

    Scenario: Unsupported Changes
      # Repeat fraud check with various unsupported events and back navigation
      When I submit a 'dob' event
      Then I get a 'update-name-date-birth' page response with context 'rfcAccountDeletion'
      When I submit a 'back' event
      Then I get a 'confirm-your-details' page response
      When I submit a 'address-dob' event
      Then I get a 'update-name-date-birth' page response with context 'rfcAccountDeletion'
      When I submit a 'back' event
      Then I get a 'confirm-your-details' page response
      When I submit a 'dob-family' event
      Then I get a 'update-name-date-birth' page response with context 'rfcAccountDeletion'
      When I submit a 'back' event
      Then I get a 'confirm-your-details' page response
      When I submit a 'dob-given' event
      Then I get a 'update-name-date-birth' page response with context 'rfcAccountDeletion'
      When I submit a 'back' event
      Then I get a 'confirm-your-details' page response
      When I submit a 'family-given' event
      Then I get a 'update-name-date-birth' page response with context 'rfcAccountDeletion'
      When I submit a 'back' event
      Then I get a 'confirm-your-details' page response
      When I submit a 'address-family-given' event
      Then I get a 'update-name-date-birth' page response with context 'rfcAccountDeletion'
      When I submit a 'back' event
      Then I get a 'confirm-your-details' page response
      When I submit a 'address-dob-family-given' event
      Then I get a 'update-name-date-birth' page response with context 'rfcAccountDeletion'
      When I submit a 'back' event
      Then I get a 'confirm-your-details' page response
      When I submit a 'address-dob-family' event
      Then I get a 'update-name-date-birth' page response with context 'rfcAccountDeletion'
      When I submit a 'back' event
      Then I get a 'confirm-your-details' page response
      When I submit a 'address-dob-given' event
      Then I get a 'update-name-date-birth' page response with context 'rfcAccountDeletion'
      When I submit a 'back' event
      Then I get a 'confirm-your-details' page response
      When I submit a 'address-family-given' event
      Then I get a 'update-name-date-birth' page response with context 'rfcAccountDeletion'

  Rule: Match M1C Fraud Check Not Applicable
    Background:
      Given the subject already has the following credentials
        | CRI     | scenario               |
        | dcmaw   | kenneth-passport-valid |
        | address | kenneth-current        |
      And the subject already has the following expired credentials
        | CRI   | scenario              |
        | fraud | kenneth-no-applicable |
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

    Scenario: Fraud 6 Months Expiry + No Update
      # Repeat fraud check with no update
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-no-applicable' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
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
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-no-applicable' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: Fraud 6 Months Expiry + Address Update
      # Repeat fraud check with update address
      When I submit a 'address-only' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details with attributes to the CRI stub
        | Attribute | Values               |
        | context   | "international_user" |
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-no-applicable' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: Fraud 6 Months Expiry + Address and Given Name Update
      # Repeat fraud check with update address and family name
      When I submit a 'given-names-and-address' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
      When I submit a 'next' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-no-applicable' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

  Rule: Match M1C Fraud Check Unavailable
    Background:
      Given the subject already has the following credentials
        | CRI     | scenario               |
        | dcmaw   | kenneth-passport-valid |
        | address | kenneth-current        |
      And the subject already has the following expired credentials
        | CRI   | scenario          |
        | fraud | kenneth-score-2   |
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

    Scenario: Fraud 6 Months Expiry + No Update
      # Repeat fraud check with no update
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-unavailable' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
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
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-unavailable' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: Fraud 6 Months Expiry + Address Update
      # Repeat fraud check with update address
      When I submit a 'address-only' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-unavailable' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: Fraud 6 Months Expiry + Address and Given Name Update
      # Repeat fraud check with update address and family name
      When I submit a 'given-names-and-address' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
      When I submit a 'next' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-unavailable' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

  Rule: Match H1A
    Scenario: Successful RFC journey
      Given the subject already has the following credentials
        | CRI     | scenario               |
        | dcmaw   | kenneth-passport-valid |
        | address | kenneth-current        |
      And the subject already has the following expired credentials
        | CRI   | scenario        |
        | fraud | kenneth-score-2 |
      When I start a new 'high-medium-confidence' journey
      Then I get a 'confirm-your-details' page response
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit expired 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P3' identity

    Scenario: Initial P2 credentials followed by high-medium confidence RFC update journey
      Given the subject already has the following credentials
        | CRI         | scenario               |
        | ukPassport  | kenneth-passport-valid |
        | address     | kenneth-current        |
        | experianKbv | kenneth-score-2        |
      And the subject already has the following expired credentials
        | CRI   | scenario        |
        | fraud | kenneth-score-2 |

      When I start a new 'high-medium-confidence' journey
      Then I get a 'confirm-your-details' page response
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response with context 'repeatFraudCheck'
      When I submit a 'update-name' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-changed-given-name-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-given-name-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response with context 'updateIdentity'
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P3' identity
