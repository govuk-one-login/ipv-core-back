@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Identity reuse update details
  Rule: Start with P2
    Background:
        Given the subject already has the following credentials
            | CRI         | scenario               |
            | ukPassport  | kenneth-passport-valid |
            | address     | kenneth-current        |
            | fraud       | kenneth-score-2        |
            | experianKbv | kenneth-score-2        |
        And I have an existing stored identity record with a 'P2' vot

    Scenario Outline: Successful name change - <selected-name-change> name change but user updates <actual-name-change> name instead
        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit a 'update-details' event
        Then I get a 'update-details' page response
        When I submit a '<selected-name-change>' event
        Then I get a 'page-update-name' page response
        When I submit a 'update-name' event
        Then I get an 'identify-device' page response
        When I submit an 'appTriage' event
        Then I get a 'pyi-triage-select-device' page response
        When I submit a 'computer-or-tablet' event
        Then I get a 'pyi-triage-select-smartphone' page response with context 'dad' and pageContext
            | Context    | Value |
            | deviceType | dad   |
        When I submit an 'android' event
        Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly' and pageContext
            | Context    | Value   |
            | smartphone | android |
            | isAppOnly  | true    |
        When the async DCMAW CRI produces a '<details>' VC
        And I poll for async DCMAW credential receipt
        Then the poll returns a '201'
        When I submit the returned journey event
        Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress' and pageContext
            | Context   | Value |
            | noAddress | true  |
        When I submit a 'next' event
        Then I get a 'fraud' CRI response
        When I submit '<fraud-details>' details with attributes to the CRI stub
            | Attribute          | Values                   |
            | evidence_requested | {"identityFraudScore":1} |
        Then I get a 'page-ipv-success' page response with context 'updateIdentity' and pageContext
            | Context     | Value |
            | journeyType | coi   |
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I am issued a 'P2' identity
        And my identity 'GivenName' is '<expected-given-name>'
        And my identity 'FamilyName' is '<expected-family-name>'
        And I have a GPG45 stored identity record type with a 'P3' vot

    Examples:
        | selected-name-change | actual-name-change | details                                    | fraud-details                       | expected-given-name | expected-family-name |
        | given-names-only     | family             | kenneth-changed-family-name-passport-valid | kenneth-changed-family-name-score-2 | Kenneth             | Smith                |
        | family-name-only     | given              | kenneth-changed-given-name-passport-valid  | kenneth-changed-given-name-score-2  | Ken                 | Decerqueira          |

    Scenario: Address Change
        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit a 'update-details' event
        Then I get a 'update-details' page response
        When I submit a 'address-only' event
        Then I get a 'address' CRI response
        When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-score-2' details with attributes to the CRI stub
            | Attribute          | Values                   |
            | evidence_requested | {"identityFraudScore":2} |
        Then I get a 'page-ipv-success' page response with context 'updateIdentity' and pageContext
            | Context     | Value |
            | journeyType | coi   |
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I am issued a 'P2' identity
        And my address 'buildingNumber' is '28'
        And I have a GPG45 stored identity record type with a 'P2' vot

    Scenario: Address and Family Name Change
        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit a 'update-details' event
        Then I get a 'update-details' page response
        When I submit a 'family-name-and-address' event
        Then I get a 'page-update-name' page response
        When I submit a 'update-name' event
        Then I get an 'identify-device' page response
        When I submit an 'appTriage' event
        Then I get a 'pyi-triage-select-device' page response
        When I submit a 'computer-or-tablet' event
        Then I get a 'pyi-triage-select-smartphone' page response with context 'dad' and pageContext
            | Context    | Value |
            | deviceType | dad   |
        When I submit an 'android' event
        Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly' and pageContext
            | Context    | Value   |
            | smartphone | android |
            | isAppOnly  | true    |
        When the async DCMAW CRI produces a 'kenneth-changed-family-name-passport-valid' VC
        And I poll for async DCMAW credential receipt
        Then the poll returns a '201'
        When I submit the returned journey event
        Then I get a 'page-dcmaw-success' page response with context 'coiAddress' and pageContext
            | Context   | Value |
            | noAddress | true  |
        When I submit a 'next' event
        Then I get a 'address' CRI response
        When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-changed-family-name-score-2' details with attributes to the CRI stub
            | Attribute          | Values                   |
            | evidence_requested | {"identityFraudScore":1} |
        Then I get a 'page-ipv-success' page response with context 'updateIdentity' and pageContext
            | Context     | Value |
            | journeyType | coi   |
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I am issued a 'P2' identity
        And my identity 'FamilyName' is 'Smith'
        And my address 'addressLocality' is 'Bristol'
        And I have a GPG45 stored identity record type with a 'P3' vot

    Scenario: Address and Given Name Change
        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit a 'update-details' event
        Then I get a 'update-details' page response
        When I submit a 'given-names-and-address' event
        Then I get a 'page-update-name' page response
        When I submit a 'update-name' event
        Then I get an 'identify-device' page response
        When I submit an 'appTriage' event
        Then I get a 'pyi-triage-select-device' page response
        When I submit a 'computer-or-tablet' event
        Then I get a 'pyi-triage-select-smartphone' page response with context 'dad' and pageContext
            | Context    | Value |
            | deviceType | dad   |
        When I submit an 'android' event
        Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly' and pageContext
            | Context    | Value   |
            | smartphone | android |
            | isAppOnly  | true    |
        When the async DCMAW CRI produces a 'kenneth-changed-given-name-passport-valid' VC
        And I poll for async DCMAW credential receipt
        Then the poll returns a '201'
        When I submit the returned journey event
        Then I get a 'page-dcmaw-success' page response with context 'coiAddress' and pageContext
            | Context   | Value |
            | noAddress | true  |
        When I submit a 'next' event
        Then I get a 'address' CRI response
        When I submit 'kenneth-changed' details to the CRI stub
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-changed-given-name-score-2' details with attributes to the CRI stub
            | Attribute          | Values                   |
            | evidence_requested | {"identityFraudScore":1} |
        Then I get a 'page-ipv-success' page response with context 'updateIdentity' and pageContext
            | Context     | Value |
            | journeyType | coi   |
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I am issued a 'P2' identity
        And my identity 'GivenName' is 'Ken'
        And my address 'addressLocality' is 'Bristol'
        And I have a GPG45 stored identity record type with a 'P3' vot

    Scenario: Unsupported Changes
        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit a 'update-details' event
        Then I get a 'update-details' page response
        When I submit a 'dob' event
        Then I get a 'update-name-date-birth' page response with context 'reuse' and pageContext
            | Context     | Value |
            | journeyType | reuse |
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'address-dob' event
        Then I get a 'update-name-date-birth' page response with context 'reuse' and pageContext
            | Context     | Value |
            | journeyType | reuse |
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'dob-family' event
        Then I get a 'update-name-date-birth' page response with context 'reuse' and pageContext
            | Context     | Value |
            | journeyType | reuse |
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'dob-given' event
        Then I get a 'update-name-date-birth' page response with context 'reuse' and pageContext
            | Context     | Value |
            | journeyType | reuse |
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'family-given' event
        Then I get a 'update-name-date-birth' page response with context 'reuse' and pageContext
            | Context     | Value |
            | journeyType | reuse |
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'address-family-given' event
        Then I get a 'update-name-date-birth' page response with context 'reuse' and pageContext
            | Context     | Value |
            | journeyType | reuse |
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'address-dob-family-given' event
        Then I get a 'update-name-date-birth' page response with context 'reuse' and pageContext
            | Context     | Value |
            | journeyType | reuse |
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'address-dob-family' event
        Then I get a 'update-name-date-birth' page response with context 'reuse' and pageContext
            | Context     | Value |
            | journeyType | reuse |
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'address-dob-given' event
        Then I get a 'update-name-date-birth' page response with context 'reuse' and pageContext
            | Context     | Value |
            | journeyType | reuse |
        When I submit a 'back' event
        Then I get a 'update-details' page response
        When I submit a 'address-family-given' event
        Then I get a 'update-name-date-birth' page response with context 'reuse' and pageContext
            | Context     | Value |
            | journeyType | reuse |
        When I submit a 'end' event
        Then I get a 'delete-handover' page response

    Scenario: Account deletion update aborted
        When I start a new 'medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit a 'update-details' event
        Then I get a 'update-details' page response
        When I submit a 'dob' event
        Then I get a 'update-name-date-birth' page response with context 'reuse' and pageContext
            | Context     | Value |
            | journeyType | reuse |
        When I submit a 'continue' event
        Then I get an OAuth response

    Scenario: Initial P2 credentials followed by high-medium confidence reuse journey - P3 met
        When I start a new 'high-medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit a 'update-details' event
        Then I get a 'update-details' page response
        When I submit a 'given-names-only' event
        Then I get a 'page-update-name' page response
        When I submit a 'update-name' event
        Then I get an 'identify-device' page response
        When I submit an 'appTriage' event
        Then I get a 'pyi-triage-select-device' page response
        When I submit a 'computer-or-tablet' event
        Then I get a 'pyi-triage-select-smartphone' page response with context 'dad' and pageContext
            | Context    | Value |
            | deviceType | dad   |
        When I submit an 'android' event
        Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly' and pageContext
            | Context    | Value   |
            | smartphone | android |
            | isAppOnly  | true    |
        When the async DCMAW CRI produces a 'kenneth-changed-given-name-passport-valid' VC
        And I poll for async DCMAW credential receipt
        Then the poll returns a '201'
        When I submit the returned journey event
        Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress' and pageContext
            | Context   | Value |
            | noAddress | true  |
        When I submit a 'next' event
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-changed-given-name-score-2' details with attributes to the CRI stub
            | Attribute          | Values                   |
            | evidence_requested | {"identityFraudScore":1} |
        Then I get a 'page-ipv-success' page response with context 'updateIdentity' and pageContext
            | Context     | Value |
            | journeyType | coi   |
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I am issued a 'P3' identity
        And I have a GPG45 stored identity record type with a 'P3' vot

  Rule: Start with P3
    Scenario: Initial P3 credentials downgraded to P2
        Given the subject already has the following credentials
          | CRI     | scenario               |
          | dcmaw   | kenneth-passport-valid |
          | address | kenneth-current        |
          | fraud   | kenneth-score-2        |
        And I have an existing stored identity record with a 'P3' vot

        When I start a new 'high-medium-confidence' journey
        Then I get a 'page-ipv-reuse' page response
        When I submit an 'update-details' event
        Then I get a 'update-details' page response
        When I submit a 'given-names-only' event
        Then I get a 'page-update-name' page response
        When I submit a 'update-name' event
        Then I get an 'identify-device' page response

        When I submit an 'appTriage' event
        Then I get a 'pyi-triage-select-device' page response
        When I submit a 'smartphone' event
        Then I get a 'pyi-triage-select-smartphone' page response with context 'mam' and pageContext
          | Context    | Value |
          | deviceType | mam   |
        When I submit an 'iphone' event
        Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly' and pageContext
          | Context    | Value  |
          | smartphone | iphone |
          | isAppOnly  | true   |
        When the async DCMAW CRI produces a 'kenneth-changed-given-name-driving-permit-valid' VC
          # And the user returns from the app to core-front
        And I pass on the DCMAW callback
        Then I get a 'check-mobile-app-result' page response
        When I poll for async DCMAW credential receipt
        Then the poll returns a '201'
        When I submit the returned journey event
        Then I get a 'drivingLicence' CRI response
        When I submit 'kenneth-changed-given-name-driving-permit-valid' details with attributes to the CRI stub
          | Attribute | Values          |
          | context   | "check_details" |
        Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress' and pageContext
          | Context   | Value |
          | noAddress | true  |
        When I submit a 'next' event
        Then I get a 'fraud' CRI response
        When I submit 'kenneth-changed-given-name-score-2' details with attributes to the CRI stub
          | Attribute          | Values                   |
          | evidence_requested | {"identityFraudScore":2} |
        Then I get a 'page-ipv-success' page response with context 'updateIdentity' and pageContext
          | Context     | Value |
          | journeyType | coi   |
        When I submit a 'next' event
        Then I get an OAuth response
        When I use the OAuth response to get my identity
        Then I am issued a 'P2' identity
        And I have a GPG45 stored identity record type with a 'P2' vot