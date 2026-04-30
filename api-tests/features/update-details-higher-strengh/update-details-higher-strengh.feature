@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Update details higher strength
  Rule: RFC Name and Address change
    Background:
      Given the subject already has the following credentials
        | CRI     | scenario               |
        | dcmaw   | kenneth-passport-valid |
        | address | kenneth-current        |
      And the subject already has the following expired credentials
        | CRI   | scenario        |
        | fraud | kenneth-score-2 |
      And I have an existing stored identity record with a 'P3' vot
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

    Scenario: RFC name and address
      When I submit a 'family-name-and-address' event
      Then I get a 'page-update-name' page response and pageContext
        | Context     | Value            |
        | journeyType | repeatFraudCheck |
      When I submit an 'update-name' event
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
      When the async DCMAW CRI produces a 'kenneth-passport-fail-no-ci' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      Then I get an 'need-more-information-confirm-change-details' page response and pageContext
        | Context              | Value             |
        | journeyType          | repeatFraudCheck  |  
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
      When the async DCMAW CRI produces a 'kenneth-changed-given-name-passport-valid' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-dcmaw-success' page response and pageContext
        | Context   | Value |
        | noAddress | true  |
      When I submit a 'next' event
      Then I get a 'address' CRI response
      When I submit 'kenneth-changed' details with attributes to the CRI stub
        | Attribute | Values               |
        | context   | "international_user" |
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-given-name-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response and pageContext
        | Context     | Value              |
        | journeyType | repeatFraudCheck   | 

    Scenario: RFC Mame change only
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response and pageContext
        | Context     | Value            |
        | journeyType | repeatFraudCheck |
      When I submit an 'update-name' event
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
      When the async DCMAW CRI produces a 'kenneth-passport-fail-no-ci' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      Then I get an 'need-more-information-confirm-change-details' page response and pageContext
        | Context              | Value             |
        | journeyType          | repeatFraudCheck  |  
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
      When the async DCMAW CRI produces a 'kenneth-changed-given-name-passport-valid' VC
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
        | Context     | Value              |
        | journeyType | repeatFraudCheck   | 
