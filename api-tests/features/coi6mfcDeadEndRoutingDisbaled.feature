# Remove this file as part of PYIC-9123
Feature: coi6mfcDeadEndRouting disabled
  Rule: Given name change only - disabled coi6mfcDeadEndRoutingEnabled
    Background:
      Given the subject already has the following credentials
      | CRI     | scenario               |
      | dcmaw   | kenneth-passport-valid |
      | address | kenneth-current        |
      And the subject already has the following expired credentials
      | CRI   | scenario        |
      | fraud | kenneth-score-2 |
      And I activate the 'coi6mfcDeadEndRoutingDisabled' feature set
      And I have an existing stored identity record with a 'P3' vot
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response and pageContext
      | Context     | Value            |
      | journeyType | repeatFraudCheck |

    Scenario: Applicable authoritative source failed check evidence too weak - disabled coi6mfcDeadEndRoutingEnabled
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
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response and pageContext
      | Context   | Value |
      | noAddress | true  |
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-no-applicable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
      Then I get an 'sorry-could-not-confirm-details' page response and pageContext
      | Context                 | Value |
      | isExistingIdentityValid | false |
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I have a stored identity record with a 'P3' max vot that is 'invalid'

    Scenario: Available authoritative source failed check evidence too weak - disabled coi6mfcDeadEndRoutingEnabled
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
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response and pageContext
      | Context   | Value |
      | noAddress | true  |
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
      Then I get an 'sorry-could-not-confirm-details' page response and pageContext
      | Context                 | Value |
      | isExistingIdentityValid | false |
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I have a stored identity record with a 'P3' max vot that is 'invalid'

    Scenario: Failed update name due to DCMAW Async
      And I submit an 'update-name' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | dad   |
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-desktop-download-app' page response and pageContext
        | Context    | Value  |
        | smartphone | iphone |
        | isAppOnly  | true   |
      When the async DCMAW CRI produces a 'kennethD' 'drivingPermit' 'fail' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get an 'update-details-failed' page response and pageContext
        | Context                   | Value |
        | isExistingIdentityInvalid | true  |
      When I submit a 'return-to-service' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity

  Rule: M1A
    Scenario: Existing M1A user cannot change name with DL and unavailable fraud check
      Given the subject already has the following credentials
      | CRI           | scenario                     |
      | dcmawAsync    | kenneth-passport-valid       |
      | address       | kenneth-current              |
      | fraud         | kenneth-score-2              |
      And I activate the 'coi6mfcDeadEndRoutingDisabled' feature set
      And I have an existing stored identity record with a 'P3' vot
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit a 'update-details' event
      Then I get a 'update-details' page response
      When I submit a 'family-name-only' event
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
      When the async DCMAW CRI produces a 'kenneth-changed-family-name-driving-permit-valid' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-changed-family-name-driving-permit-valid' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response and pageContext
      | Context   | Value |
      | noAddress | true  |
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-changed-family-name-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
      Then I get an 'sorry-could-not-confirm-details' page response and pageContext
      | Context                 | Value |
      | isExistingIdentityValid | true  |
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P2' identity

  Rule: Update given name only - disabled coi6mfcDeadEndRoutingEnabled
    Background:
      Given the subject already has the following credentials
      | CRI     | scenario               |
      | dcmaw   | kenneth-passport-valid |
      | address | kenneth-current        |
      | fraud   | kenneth-score-2        |
      And I activate the 'coi6mfcDeadEndRoutingDisabled' feature set
      And I have an existing stored identity record with a 'P3' vot
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit an 'update-details' event
      Then I get an 'update-details' page response
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response

    Scenario: Zero score in fraud CRI - receives old identity (P2)
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
      When the async DCMAW CRI produces a 'kennethD' 'drivingPermit' 'success' VC
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
      When I submit 'kenneth-changed-given-name-score-0' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
      Then I get an 'sorry-could-not-confirm-details' page response and pageContext
      | Context                 | Value |
      | isExistingIdentityValid | true  |
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P2' identity

    Scenario: fail-with-no-ci from DCMAW
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
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get an 'update-details-failed' page response
      When I submit a 'continue' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P2' identity
      And I have a stored identity record with a 'P3' max vot
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-reuse' page response
