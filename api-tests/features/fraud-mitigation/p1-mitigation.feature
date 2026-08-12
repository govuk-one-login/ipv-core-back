@Build @QualityGateIntegrationTest @QualityGateNewFeatureTest
Feature: P1 Fraud mitigation
  Background: Enable fraud mitigation
    Given I activate the 'mitigations9020' feature set

  Rule: No photo ID journey
    Background: Start P1 no photo id
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response and pageContext
        | Context  | Value |
        | ninoOnly | true  |
      When I submit an 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details with attributes to the CRI stub
        | Attribute | Values         |
        | context   | "hmrc_check" |
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

    Scenario Outline: Breaching fraud CI goes to mitigation route - Happy path DAD journey - <device>
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'useApp' event
      Then I get a 'passport-biometric-chip' page response
      When I submit a 'next' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | dad   |
      When I submit an '<device>' event
      Then I get a 'pyi-triage-desktop-download-app' page response and pageContext
        | Context    | Value    |
        | smartphone | <device> |
        | isAppOnly  | true     |
      When the async DCMAW CRI produces a 'kenneth-passport-valid' VC that mitigates the 'NEEDS-LIVENESS-LIKENESS' CI
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P1' identity
      And I have a stored identity record with a 'P3' max vot

      Examples:
        | device  |
        | iphone  |
        | android |

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

    Scenario: Breaching fraud CI goes to mitigation route - user start new journey
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      # New journey
      When I start a new 'low-confidence' journey
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'useApp' event
      Then I get a 'passport-biometric-chip' page response

    Scenario: Breaching fraud CI goes back to RP
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      # New journey
      When I start a new 'low-confidence' journey
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

  Rule: Photo ID app journey
    Background: Start P1 driving licence app journey
      When I start a new 'low-confidence' journey
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

    Scenario: Breaching fraud CI goes to mitigation route - Happy path MAM journey - <device>
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-passport' page response
      When I submit a 'retryPassport' event
      Then I get a 'passport-biometric-chip' page response
      When I submit a 'next' event
      Then I get a 'pyi-triage-desktop-download-app' page response and pageContext
        | Context    | Value  |
        | smartphone | iphone |
        | isAppOnly  | true   |
      When the async DCMAW CRI produces a 'kenneth-passport-valid' VC that mitigates the 'NEEDS-LIVENESS-LIKENESS' CI
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P1' identity
      And I have a stored identity record with a 'P3' max vot

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

  Rule: Combined CI score breach
    Scenario: Combined breaching fraud CI goes to mitigation route
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response and pageContext
        | Context  | Value |
        | ninoOnly | true  |
      When I submit an 'next' event
      Then I get a 'claimedIdentity' CRI response
      When I submit 'kenneth-current' details with attributes to the CRI stub
        | Attribute | Values         |
        | context   | "hmrc_check" |
      Then I get a 'nino' CRI response

      # First non breaching CI
      When I submit 'kenneth-score-2-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response

      # Second CI
      When I submit 'kenneth-score-2-liveness-likeness-p1-when-combined-with-non-breaching' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'useApp' event
      Then I get a 'passport-biometric-chip' page response

      # Mitigation journey
      When I submit a 'next' event
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

      # Mitigate second CI
      When the async DCMAW CRI produces a 'kenneth-passport-valid' VC that mitigates the 'NEEDS-LIVENESS-LIKENESS-P1-WHEN-COMBINED-WITH-NON-BREACHING' CI
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P1' identity
      And I have a stored identity record with a 'P3' max vot

  Rule: Web document journey
    Background: Start P1 web document journey
      When I start a new 'low-confidence' journey
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
      Then I get a 'page-multiple-doc-check' page response and pageContext
        | Context   | Value |
        | allowNino | true  |

    Scenario Outline: Non-breaching, failing fraud CI fails <cri> journey
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

    Scenario Outline: Breaching fraud CI after <cri> goes to mitigation route
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
      When I submit a 'next' event
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
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P1' identity
      And I have a stored identity record with a 'P3' max vot

      Examples:
        | cri            | details                      |
        | drivingLicence | kenneth-driving-permit-valid |
        | ukPassport     | kenneth-passport-valid       |

  Rule: F2F journey
    Background: Start P1 F2F journey
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response and pageContext
        | Context  | Value |
        | ninoOnly | true  |
      When I submit an 'end' event
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
      When I submit a 'next' event
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
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P1' identity
      And I have a stored identity record with a 'P3' max vot

  Rule: Fraud CI mitigation failed by using driving licence
    Scenario: User failed to mitigate Fraud CI by using driving licence in app:
      When I start a new 'low-confidence' journey
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
      Then I get a 'page-multiple-doc-check' page response and pageContext
        | Context   | Value |
        | allowNino | true  |
      When I submit a 'drivingLicence' event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'useApp' event
      Then I get a 'passport-biometric-chip' page response
      When I submit a 'abandon' event
      Then I get a 'need-biometric-passport' page response
      When I submit a 'useApp' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | mam   |
      When I submit an 'android' event
      Then I get a 'pyi-triage-mobile-download-app' page response and pageContext
        | Context    | Value   |
        | smartphone | android |
        | isAppOnly  | true    |
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
      And I pass on the DCMAW callback
      Then I get an 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      # User passed DL check but doesn't have sufficient score to achieve P2
      Then I get an 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

  Rule: Failed DCMAW async and alternative routes
    Background:
      When I start a new 'low-confidence' journey
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
      Then I get a 'page-multiple-doc-check' page response and pageContext
        | Context   | Value |
        | allowNino | true  |
      When I submit a 'drivingLicence' event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-breaching-liveness-likeness-ci' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'retry-prove-identity-app' page response
      When I submit a 'useApp' event
      Then I get a 'passport-biometric-chip' page response
      When I submit a 'abandon' event
      Then I get a 'need-biometric-passport' page response
      When I submit a 'useApp' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event

    Scenario: User navigates back on select device page
      Then I get a 'pyi-triage-select-device' page response
      When I submit an 'back' event
      Then I get a 'need-biometric-passport' page response
      When I submit a 'useApp' event
      Then I get an 'identify-device' page response

    Scenario: User failed to mitigate Fraud CI:
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | mam   |
      When I submit an 'android' event
      Then I get a 'pyi-triage-mobile-download-app' page response and pageContext
        | Context    | Value   |
        | smartphone | android |
        | isAppOnly  | true    |
      When the async DCMAW CRI produces a 'kenneth-passport-fail-no-ci' VC
      And I pass on the DCMAW callback
      Then I get an 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get an 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

    Scenario: User failed to mitigate Fraud CI with new CI:
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | mam   |
      When I submit an 'android' event
      Then I get a 'pyi-triage-mobile-download-app' page response and pageContext
        | Context    | Value   |
        | smartphone | android |
        | isAppOnly  | true    |
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC with a 'BREACHING' CI
      And I pass on the DCMAW callback
      Then I get an 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get an 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS

    Scenario: User failed to mitigate Fraud CI by using driving licence in app:
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response and pageContext
        | Context    | Value |
        | deviceType | mam   |
      When I submit an 'android' event
      Then I get a 'pyi-triage-mobile-download-app' page response and pageContext
        | Context    | Value   |
        | smartphone | android |
        | isAppOnly  | true    |
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
      And I pass on the DCMAW callback
      Then I get an 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      # User passed DL check but doesn't have sufficient score to achieve P2
      Then I get an 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I am issued a 'P0' identity
      And I don't have a stored identity in EVCS
