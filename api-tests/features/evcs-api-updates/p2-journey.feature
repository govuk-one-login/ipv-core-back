@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: P2 EvcsUpdates journeys
  Rule: Medium-confidence journeys
    Background:
      Given I activate the 'evcsApiUpdates' feature set
      And I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | dad   |

    Scenario: Successful M1C P2 identity
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-desktop-download-app' page response and pageContext
        | Context    | Value  |
        | smartphone | iphone |
        | isAppOnly  | false  |
      When the async DCMAW CRI produces a 'kenneth-passport-valid' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-unavailable' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P2' identity
      And I have a stored identity record with a 'P2' max vot

  Rule: Successful F2F journeys
    Scenario Outline: Successful P2 identity via F2F using <doc> - <journey-type>
      # Initial journey
      Given I activate the 'evcsApiUpdates' feature set
      And I start a new '<journey-type>' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit a 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'f2f' CRI response
      When I submit '<details>' details with attributes to the async CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new '<journey-type>' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P2' identity
      And I have a stored identity record with a 'P2' max vot

      Examples:
        | journey-type           | doc      | details                      |
        | high-medium-confidence | passport | kenneth-passport-valid       |
        | medium-confidence      | DL       | kenneth-driving-permit-valid |

  Rule: Reuse journey
    Scenario: Successful P2 reuse journey
    # First identity proving journey
      Given I activate the 'evcsApiUpdates' feature set
      And I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | mam   |
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response and pageContext
        | Context    | Value  |
        | smartphone | iphone |
        | isAppOnly  | false  |
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P2' identity
      And I have a stored identity record with a 'P3' max vot

    # Reuse journey
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      And my proven user details match
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P2' identity
      And I have a stored identity record with a 'P3' max vot

  Rule: Match M1B
    Background: Start journey with expired fraud check
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
      And the subject already has the following expired credentials
        | CRI   | scenario        |
        | fraud | kenneth-score-2 |
      And I activate the 'evcsApiUpdates' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'confirm-your-details' page response

    Scenario: Fraud 6 Months Expiry + No Update
      # Repeat fraud check with no update
      When I submit a 'next' event
      Then I get a 'fraud' CRI response
      When I submit expired 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-ipv-success' page response and pageContext
        | Context     | Value |
        | journeyType | coi   |
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P2' identity
      And I have a stored identity record with a 'P2' max vot

    Scenario: Fraud 6 Months Expiry + Given Name Update
      # Repeat fraud check with update name
      When I submit a 'given-names-only' event
      Then I get a 'page-update-name' page response and pageContext
        | Context     | Value            |
        | journeyType | repeatFraudCheck |
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
        | Context     | Value |
        | journeyType | coi   |
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P2' identity
      And my identity 'GivenName' is 'Ken'
      And my identity 'FamilyName' is 'Decerqueira'
      And I have a stored identity record with a 'P3' max vot
