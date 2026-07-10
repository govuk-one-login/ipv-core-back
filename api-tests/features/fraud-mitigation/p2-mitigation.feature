@Build @QualityGateIntegrationTest @QualityGateNewFeatureTest
Feature: P2 Fraud mitigation
  Background: Enable fraud mitigation
    Given I activate the 'mitigations9020' feature set

  Rule: No photo ID journey - no Open Banking
    Background: Start P2 no photo id
      Given I activate the 'openBankingDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details with attributes to the CRI stub
        | Attribute | Values         |
        | context   | "bank_account" |
      Then I get a 'bav' CRI response
      When I submit 'kenneth' details to the CRI stub
      Then I get a 'nino' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response

    Scenario: Non-breaching, non-failing fraud CI continues on journey - no Open Banking
      When I submit 'kenneth-score-2-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'personal-independence-payment' page response

    Scenario: Non-breaching, failing fraud CI fails journey - no Open Banking
      When I submit 'kenneth-score-0-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

    Scenario: Breaching fraud CI goes to mitigation route - no Open Banking
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'useApp' event
      Then I get a 'passport-biometric-chip' page response

    Scenario: Breaching fraud CI goes back to RP - no Open Banking
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

  Rule: No photo ID journey
    Background: Start P2 no photo id
      Given I activate the 'openBanking' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-online' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details with attributes to the CRI stub
        | Attribute | Values         |
        | context   | "bank_account" |
      Then I get a 'bav' CRI response
      When I submit 'kenneth' details to the CRI stub
      Then I get a 'nino' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response

    Scenario: Non-breaching, non-failing fraud CI continues on journey
      When I submit 'kenneth-score-2-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'personal-independence-payment' page response

    Scenario: Non-breaching, failing fraud CI fails journey
      When I submit 'kenneth-score-0-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

    Scenario: Breaching fraud CI goes to mitigation route
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'useApp' event
      Then I get a 'passport-biometric-chip' page response

    Scenario: Breaching fraud CI goes back to RP
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

  Rule: Photo ID app journey
    Background: Start P2 driving licence app journey
      When I start a new 'medium-confidence' journey
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
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-desktop-download-app' page response and pageContext
        | Context    | Value  |
        | smartphone | iphone |
        | isAppOnly  | false  |
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response

    Scenario: Non-breaching, non-failing fraud CI continues on journey
      When I submit 'kenneth-score-2-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-ipv-success' page response

    Scenario: Non-breaching, failing fraud CI fails journey
      When I submit 'kenneth-score-0-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

    Scenario: Breaching fraud CI goes to mitigation route
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-passport' page response
      When I submit a 'retryPassport' event
      Then I get a 'passport-biometric-chip' page response

    Scenario: Breaching fraud CI goes back to RP
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-passport' page response
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

  Rule: Chipped passport auto-mitigation
    Scenario: Chipped passport auto-mitigates breaching fraud CI
      When I start a new 'medium-confidence' journey
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
      When I tell the CIMIT stub that the 'BREACHING' CI is already mitigated
      And  I submit 'kenneth-score-0-mortality-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":1} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P2' identity with a fraud VC
      And I have a stored identity record with a 'P2' max vot

  Rule: Combined CI score breach
    Scenario: Combined breaching fraud CI goes to mitigation route - no Open Banking
      Given I activate the 'openBankingDisabled' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details with attributes to the CRI stub
        | Attribute | Values         |
        | context   | "bank_account" |
      Then I get a 'bav' CRI response
      When I submit 'kenneth' details to the CRI stub
      Then I get a 'nino' CRI response
      When I submit 'kenneth-score-2-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2-liveness-likeness-p2-when-combined-with-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'useApp' event
      Then I get a 'passport-biometric-chip' page response

    Scenario: Combined breaching fraud CI goes to mitigation route
      Given I activate the 'openBanking' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-online' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details with attributes to the CRI stub
        | Attribute | Values         |
        | context   | "bank_account" |
      Then I get a 'bav' CRI response
      When I submit 'kenneth' details to the CRI stub
      Then I get a 'nino' CRI response
      When I submit 'kenneth-score-2-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2-liveness-likeness-p2-when-combined-with-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'useApp' event
      Then I get a 'passport-biometric-chip' page response

  Rule: Web document journey - no Open Banking
    Background: Start P2 web document journey
      Given I activate the 'openBankingDisabled' feature set
      When I start a new 'medium-confidence' journey
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
      When I submit a 'neither' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-multiple-doc-check' page response

    Scenario Outline: Non-breaching, failing fraud CI fails <cri> journey - no Open Banking
      When I submit a '<cri>' event
      Then I get a '<cri>' CRI response
      When I submit '<details>' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-0-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

      Examples:
        | cri            | details                      |
        | drivingLicence | kenneth-driving-permit-valid |
        | ukPassport     | kenneth-passport-valid       |

    Scenario Outline: Breaching fraud CI after <cri> goes to mitigation route - no Open Banking
      When I submit a '<cri>' event
      Then I get a '<cri>' CRI response
      When I submit '<details>' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'useApp' event
      Then I get a 'passport-biometric-chip' page response

      Examples:
        | cri            | details                      |
        | drivingLicence | kenneth-driving-permit-valid |
        | ukPassport     | kenneth-passport-valid       |

  Rule: Web document journey
    Background: Start P2 web document journey
      Given I activate the 'openBanking' feature set
      When I start a new 'medium-confidence' journey
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
      When I submit a 'neither' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'select-photo-id' page response

    Scenario Outline: Non-breaching, failing fraud CI fails <cri> journey
      When I submit a '<cri>' event
      Then I get a 'prove-identity-online' page response and pageContext
        | Context | Value |
        | photoId | true  |
      When I submit a 'next' event
      Then I get a 'prove-identity-online-banking' page response
      When I submit a 'next' event
      Then I get a '<cri>' CRI response
      When I submit '<details>' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-0-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

      Examples:
        | cri            | details                      |
        | drivingLicence | kenneth-driving-permit-valid |
        | ukPassport     | kenneth-passport-valid       |

    Scenario Outline: Breaching fraud CI after <cri> goes to mitigation route
      When I submit a '<cri>' event
      Then I get a 'prove-identity-online' page response and pageContext
        | Context | Value |
        | photoId | true  |
      When I submit a 'next' event
      Then I get a 'prove-identity-online-banking' page response
      When I submit a 'next' event
      Then I get a '<cri>' CRI response
      When I submit '<details>' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'useApp' event
      Then I get a 'passport-biometric-chip' page response

      Examples:
        | cri            | details                      |
        | drivingLicence | kenneth-driving-permit-valid |
        | ukPassport     | kenneth-passport-valid       |

  Rule: F2F journey - no Open Banking
    Background: Start P2 F2F journey
      Given I activate the 'openBankingDisabled' feature set
      When I start a new 'medium-confidence' journey
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

    Scenario: Non-breaching, failing fraud CI fails journey - no Open Banking
      When I submit 'kenneth-score-0-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

    Scenario: Breaching fraud CI goes to mitigation route - no Open Banking
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'useApp' event
      Then I get a 'passport-biometric-chip' page response

  Rule: F2F journey
    Background: Start P2 F2F journey
      Given I activate the 'openBanking' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-online' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit a 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response

    Scenario: Non-breaching, failing fraud CI fails journey
      When I submit 'kenneth-score-0-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

    Scenario: Breaching fraud CI goes to mitigation route
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'useApp' event
      Then I get a 'passport-biometric-chip' page response