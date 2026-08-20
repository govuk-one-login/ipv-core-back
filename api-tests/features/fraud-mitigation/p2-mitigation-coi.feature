@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Identity reuse update details
    Background: Start journey with existing identity
      Given I activate the 'mitigations9020' feature set
      And the subject already has the following credentials
        | CRI     | scenario               |
        | dcmaw   | kenneth-passport-valid |
        | address | kenneth-current        |
        | fraud   | kenneth-score-2        |
      And I have an existing stored identity record with a 'P3' vot
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit a 'update-details' event
      Then I get a 'update-details' page response

    Scenario: Update Given Name with Fraud CI mitigation
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | dad   |
      When I submit an 'android' event
      Then I get a 'pyi-triage-desktop-download-app' page response and pageContext
        | Context    | Value   |
        | smartphone | android |
        | isAppOnly  | true    |
      When the async DCMAW CRI produces a 'kenneth-changed-given-name-driving-permit-valid' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response and pageContext
        | Context   | Value |
        | noAddress | true  |
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get an 'need-more-information-confirm-change-details' page response and pageContext
        | Context              | Value         |
        | journeyType          | updateDetails |
      When I submit an 'passport' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | dad   |
      When I submit an 'android' event
      Then I get a 'pyi-triage-desktop-download-app' page response and pageContext
        | Context    | Value   |
        | smartphone | android |
        | isAppOnly  | true    |
      When the async DCMAW CRI produces a 'kenneth-changed-given-name-passport-valid' VC that mitigates the 'NEEDS-LIVENESS-LIKENESS' CI
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-dcmaw-success' page response and pageContext
        | Context   | Value |
        | noAddress | true  |
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-given-name-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response and pageContext
        | Context     | Value |
        | journeyType | coi   |

    Scenario: Update Address with Fraud CI mitigation
      When I submit a 'address-only' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details with attributes to the CRI stub
        | Attribute | Values               |
        | context   | "international_user" |
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get an 'need-more-information-confirm-change-details' page response and pageContext
        | Context              | Value         |
        | journeyType          | updateDetails |
      When I submit an 'passport' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | dad   |
      When I submit an 'android' event
      Then I get a 'pyi-triage-desktop-download-app' page response and pageContext
        | Context    | Value   |
        | smartphone | android |
        | isAppOnly  | true    |
      When the async DCMAW CRI produces a 'kenneth-passport-valid' VC that mitigates the 'NEEDS-LIVENESS-LIKENESS' CI
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-dcmaw-success' page response and pageContext
        | Context   | Value |
        | noAddress | true  |
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response and pageContext
        | Context     | Value |
        | journeyType | coi   |

    Scenario: Update details - Given Name and Address with Fraud CI mitigation
      When I submit a 'given-names-and-address' event
      Then I get a 'page-update-name' page response
      When I submit a 'update-name' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | dad   |
      When I submit an 'android' event
      Then I get a 'pyi-triage-desktop-download-app' page response and pageContext
        | Context    | Value   |
        | smartphone | android |
        | isAppOnly  | true    |
      When the async DCMAW CRI produces a 'kenneth-changed-given-name-driving-permit-valid' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-changed-given-name-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response and pageContext
        | Context   | Value |
        | noAddress | true  |
      When I submit a 'next' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details to the CRI stub
      Then I get a 'fraud' CRI response

      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get an 'need-more-information-confirm-change-details' page response and pageContext
        | Context              | Value         |
        | journeyType          | updateDetails |
      When I submit an 'passport' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | dad   |
      When I submit an 'android' event
      Then I get a 'pyi-triage-desktop-download-app' page response and pageContext
        | Context    | Value   |
        | smartphone | android |
        | isAppOnly  | true    |
      When the async DCMAW CRI produces a 'kenneth-changed-given-name-passport-valid' VC that mitigates the 'NEEDS-LIVENESS-LIKENESS' CI
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-given-name-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response and pageContext
        | Context     | Value |
        | journeyType | coi   |
