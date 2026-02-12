@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: International identity reuse update details
    Background:
        Given the subject already has the following credentials
            | CRI     | scenario               |
            | dcmaw   | kenneth-passport-valid |
            | address | kenneth-current        |
            | fraud   | kenneth-no-applicable   |
        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        And I submit a 'update-details' event
        Then I get a 'update-details' page response

    Scenario: International Address Change
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
        And my address 'buildingNumber' is '28'

    Scenario: International Address and Family Name Change
        When I submit a 'family-name-and-address' event
        Then I get a 'page-update-name' page response
        When I submit a 'update-name' event
        Then I get an 'identify-device' page response
        When I submit an 'appTriage' event
        Then I get a 'pyi-triage-select-device' page response
        When I submit a 'computer-or-tablet' event
        Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
        When I submit an 'android' event
        Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly'
        When the async DCMAW CRI produces a 'kenneth-changed-family-name-passport-valid' VC
        And I poll for async DCMAW credential receipt
        Then the poll returns a '201'
        When I submit the returned journey event
        Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
        When I submit a 'next' event
        Then I get a 'address' CRI response
        When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-changed-family-name-and-address-no-applicable' details with attributes to the CRI stub
            | Attribute          | Values                   |
            | evidence_requested | {"identityFraudScore":1} |
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
        Then I get an 'identify-device' page response
        When I submit an 'appTriage' event
        Then I get a 'pyi-triage-select-device' page response
        When I submit a 'computer-or-tablet' event
        Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
        When I submit an 'android' event
        Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly'
        When the async DCMAW CRI produces a 'kenneth-changed-given-name-passport-valid' VC
        And I poll for async DCMAW credential receipt
        Then the poll returns a '201'
        When I submit the returned journey event
        Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
        When I submit a 'next' event
        Then I get a 'address' CRI response
        When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-changed-given-name-and-address-no-applicable' details with attributes to the CRI stub
            | Attribute          | Values                   |
            | evidence_requested | {"identityFraudScore":1} |
        Then I get a 'page-ipv-success' page response with context 'updateIdentity'
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I get a 'P2' identity
        And my identity 'GivenName' is 'Ken'
        And my address 'streetName' is 'King Road'
