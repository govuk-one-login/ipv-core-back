@Build
Feature: International identity reuse update details

    Background:
        Given the subject already has the following credentials
            | CRI     | scenario               |
            | dcmaw   | kenneth-passport-valid |
            | address | kenneth-current        |
            | fraud   | kenneth-no-applicable   |
        And I activate the 'disableStrategicApp' feature set
        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I activate the 'internationalAddress' feature sets
        And I submit a 'update-details' event
        Then I get a 'update-details' page response

    Scenario: International Address Change
        When I submit a 'address-only' event
        Then I get a 'address' CRI response
        When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-no-applicable' details to the CRI stub
        Then I get a 'page-ipv-success' page response with context 'updateIdentity'
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I get a 'P2' identity
        And my address 'buildingNumber' is '28'

    Scenario: International Address and Family Name Change
        When I submit a 'family-name-and-address' event
        Then I get a 'page-update-name' page response
        When I submit a 'update-name' event
        Then I get a 'dcmaw' CRI response
        When I submit 'kenneth-changed-family-name-passport-valid' details to the CRI stub
        Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
        When I submit a 'next' event
        Then I get a 'address' CRI response
        When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-changed-family-name-and-address-no-applicable' details to the CRI stub
        Then I get a 'page-ipv-success' page response with context 'updateIdentity'
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I get a 'P2' identity
        And my identity 'FamilyName' is 'Smith'
        And my address 'addressLocality' is 'Bristol'

    Scenario: International Address and Given Name Change
        When I submit a 'given-names-and-address' event
        Then I get a 'page-update-name' page response
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
        When I submit 'kenneth-changed-given-name-and-address-no-applicable' details to the CRI stub
        Then I get a 'page-ipv-success' page response with context 'updateIdentity'
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I get a 'P2' identity
        And my identity 'GivenName' is 'Ken'
        And my address 'streetName' is 'King Road'
