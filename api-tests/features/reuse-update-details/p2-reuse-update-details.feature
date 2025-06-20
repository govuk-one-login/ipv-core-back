@Build
Feature: Identity reuse update details
    Background:
        Given the subject already has the following credentials
            | CRI     | scenario               |
            | dcmaw   | kenneth-passport-valid |
            | address | kenneth-current        |
            | fraud   | kenneth-score-2        |
        And I activate the 'disableStrategicApp' feature set
        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit a 'update-details' event
        Then I get a 'update-details' page response

    Scenario Outline: Successful name change - <selected-name-change> name change but user updates <actual-name-change> name instead
        When I submit a '<selected-name-change>' event
        Then I get a 'page-update-name' page response
        When I submit a 'update-name' event
        Then I get a 'dcmaw' CRI response
        When I submit '<details>' details to the CRI stub
        Then I get a 'drivingLicence' CRI response
        When I submit '<details>' details with attributes to the CRI stub
            | Attribute | Values          |
            | context   | "check_details" |
        Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
        When I submit a 'next' event
        Then I get a 'fraud' CRI response
        When I submit '<fraud-details>' details with attributes to the CRI stub
            | Attribute          | Values                   |
            | evidence_requested | {"identityFraudScore":2} |
        Then I get a 'page-ipv-success' page response with context 'updateIdentity'
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I get a 'P2' identity
        And my identity 'GivenName' is '<expected-given-name>'
        And my identity 'FamilyName' is '<expected-family-name>'

    Examples:
        | selected-name-change | actual-name-change | details                                          | fraud-details                       | expected-given-name | expected-family-name |
        | given-names-only     | family             | kenneth-changed-family-name-driving-permit-valid | kenneth-changed-family-name-score-2 | Kenneth             | Smith                |
        | family-name-only     | given              | kenneth-changed-given-name-driving-permit-valid  | kenneth-changed-given-name-score-2  | Ken                 | Decerqueira          |

    Scenario: Address Change
        When I submit a 'address-only' event
        Then I get a 'address' CRI response
        When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-score-2' details with attributes to the CRI stub
            | Attribute          | Values                   |
            | evidence_requested | {"identityFraudScore":1} |
        Then I get a 'page-ipv-success' page response with context 'updateIdentity'
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I get a 'P2' identity
        And my address 'buildingNumber' is '28'

    Scenario: Address and Family Name Change
        When I submit a 'family-name-and-address' event
        Then I get a 'page-update-name' page response
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

    Scenario: Address and Given Name Change
        When I submit a 'given-names-and-address' event
        Then I get a 'page-update-name' page response
        When I submit a 'update-name' event
        Then I get a 'dcmaw' CRI response
        When I submit 'kenneth-changed-given-name-driving-permit-valid' details to the CRI stub
        Then I get a 'drivingLicence' CRI response
        When I submit 'kenneth-changed-given-name-driving-permit-valid' details with attributes to the CRI stub
            | Attribute | Values          |
            | context   | "check_details" |
        Then I get a 'page-dcmaw-success' page response with context 'coiAddress'

    Scenario: Unsupported Changes
        When I submit a 'dob' event
        Then I get a 'update-name-date-birth' page response with context 'reuse'
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'address-dob' event
        Then I get a 'update-name-date-birth' page response with context 'reuse'
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'dob-family' event
        Then I get a 'update-name-date-birth' page response with context 'reuse'
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'dob-given' event
        Then I get a 'update-name-date-birth' page response with context 'reuse'
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'family-given' event
        Then I get a 'update-name-date-birth' page response with context 'reuse'
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'address-family-given' event
        Then I get a 'update-name-date-birth' page response with context 'reuse'
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'address-dob-family-given' event
        Then I get a 'update-name-date-birth' page response with context 'reuse'
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'address-dob-family' event
        Then I get a 'update-name-date-birth' page response with context 'reuse'
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'address-dob-given' event
        Then I get a 'update-name-date-birth' page response with context 'reuse'
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'address-family-given' event
        Then I get a 'update-name-date-birth' page response with context 'reuse'
        When I submit a 'end' event
        Then I get a 'delete-handover' page response

    Scenario: Account deletion update aborted
        When I submit a 'dob' event
        Then I get a 'update-name-date-birth' page response with context 'reuse'
        When I submit a 'continue' event
        Then I get an OAuth response
