@Build
Feature: Identity reuse update details

    Background:
        Given the subject already has the following credentials
            | CRI     | scenario                     |
            | dcmaw   | kenneth-driving-permit-valid |
            | address | kenneth-current              |
            | fraud   | kenneth-score-2              |
        When I start a new 'medium-confidence' journey
        And I activate the 'internationalAddress' feature sets
        Then I get a 'page-ipv-reuse' page response
        When I submit a 'update-details' event
        Then I get a 'update-details' page response

    Scenario: Address Change
        When I submit a 'address-only' event
        Then I get a 'address' CRI response
        When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-score-2' details to the CRI stub
        Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
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
        Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
        When I submit a 'next' event
        Then I get a 'address' CRI response
        When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-changed-family-name-score-2' details to the CRI stub
        Then I get a 'page-ipv-success' page response
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
        Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
        When I submit a 'next' event
        Then I get a 'address' CRI response
        When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-changed-given-name-score-2' details to the CRI stub
        Then I get a 'page-ipv-success' page response
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I get a 'P2' identity
        And my identity 'GivenName' is 'Ken'
        And my address 'streetName' is 'King Road'