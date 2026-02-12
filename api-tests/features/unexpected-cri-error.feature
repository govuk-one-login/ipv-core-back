@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Handling unexpected CRI errors
  Rule: Driving Licence and Passport CRIs
    Background: Go through web route
      Given  I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit a 'neither' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-multiple-doc-check' page response

    Scenario Outline: Unexpected error from <cri> - try CRI again
      When I submit a '<cri>' event
      Then I get a '<cri>' CRI response
      When I call the CRI stub and get a 'server_error' OAuth error
      Then I get a 'sorry-technical-problem' page response
      When I submit a 'tryAgain' event
      Then I get a '<cri>' CRI response
      When I submit '<details>' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | cri            | details                      |
        | ukPassport     | kenneth-passport-valid       |
        | drivingLicence | kenneth-driving-permit-valid |

    Scenario Outline: Unexpected error from <cri> - try app route
      When I submit a '<cri>' event
      Then I get a '<cri>' CRI response
      And I call the CRI stub and get a 'server_error' OAuth error
      Then I get a 'sorry-technical-problem' page response
      When I submit an 'app' event
      Then I get a 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
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
      Then I get a 'P2' identity

      Examples:
        | cri            |
        | ukPassport     |
        | drivingLicence |

    Scenario Outline: Unexpected error from <cri> - try post office route
      When I submit a '<cri>' event
      Then I get a '<cri>' CRI response
      When I call the CRI stub and get a 'server_error' OAuth error
      Then I get a 'sorry-technical-problem' page response
      When I submit an 'postOffice' event
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
      When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | cri            | details                      |
        | ukPassport     | kenneth-passport-valid       |
        | drivingLicence | kenneth-driving-permit-valid |

    Scenario Outline: Unexpected error from <cri> - return to RP
      When I submit a '<cri>' event
      Then I get a '<cri>' CRI response
      When I call the CRI stub and get a 'server_error' OAuth error
      Then I get a 'sorry-technical-problem' page response
      When I submit an 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

      Examples:
        | cri            |
        | ukPassport     |
        | drivingLicence |

    Scenario Outline: CI from <ci_cri> then unexpected error twice from <mitigating_cri> before success
      When I submit a '<ci_cri>' event
      Then I get a '<ci_cri>' CRI response
      When I submit '<ci_details>' details to the CRI stub
      Then I get a '<noMatchPage>' page response
      When I submit a 'next' event
      Then I get a '<mitigating_cri>' CRI response
      When I call the CRI stub and get a 'server_error' OAuth error
      Then I get a 'sorry-technical-problem' page response with context 'dlOrPassportMitigation'
      When I submit a 'tryAgain' event
      Then I get a '<mitigating_cri>' CRI response
      When I call the CRI stub and get a 'server_error' OAuth error
      Then I get a 'sorry-technical-problem' page response with context 'dlOrPassportMitigation'
      When I submit a 'tryAgain' event
      Then I get a '<mitigating_cri>' CRI response
      When I submit '<mitigating_details>' details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | ci_cri            | ci_details                                 | noMatchPage                              | mitigating_cri | mitigating_details           |
        | ukPassport        | kenneth-passport-needs-alternate-doc       | pyi-passport-no-match-another-way        | drivingLicence | kenneth-driving-permit-valid |
        | drivingLicence    | kenneth-driving-permit-needs-alternate-doc | pyi-driving-licence-no-match-another-way | ukPassport     | kenneth-passport-valid       |

    Scenario Outline: CI from <ci_cri> then separate session unexpected error twice from <mitigating_cri> before success
      When I submit a '<ci_cri>' event
      Then I get a '<ci_cri>' CRI response
      When I submit '<ci_details>' details to the CRI stub
      Then I get a '<noMatchPage>' page response
      When I submit a 'next' event
      Then I get a '<mitigating_cri>' CRI response

      # User drops out of previous CRI without mitigating and starts a new journey
      Given I start a new 'medium-confidence' journey
      Then I get a '<separateSessionNoMatch>' page response
      When I submit a 'next' event
      Then I get a '<mitigationStart>' page response
      When I submit a 'next' event
      Then I get a '<mitigating_cri>' CRI response
      When I call the CRI stub and get a 'server_error' OAuth error
      Then I get a 'sorry-technical-problem' page response with context 'dlOrPassportMitigation'
      When I submit a 'tryAgain' event
      Then I get a '<mitigating_cri>' CRI response
      When I call the CRI stub and get a 'server_error' OAuth error
      Then I get a 'sorry-technical-problem' page response with context 'dlOrPassportMitigation'
      When I submit a 'tryAgain' event
      Then I get a '<mitigating_cri>' CRI response
      When I submit '<mitigating_details>' details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | ci_cri            | ci_details                                 | noMatchPage                              | separateSessionNoMatch       | mitigationStart                   | mitigating_cri | mitigating_details           |
        | ukPassport        | kenneth-passport-needs-alternate-doc       | pyi-passport-no-match-another-way        | pyi-passport-no-match        | pyi-continue-with-driving-licence | drivingLicence | kenneth-driving-permit-valid |
        | drivingLicence    | kenneth-driving-permit-needs-alternate-doc | pyi-driving-licence-no-match-another-way | pyi-driving-licence-no-match | pyi-continue-with-passport        | ukPassport     | kenneth-passport-valid       |

    Scenario Outline: CI from <ci_cri> then unexpected error from <mitigating_cri> and return to RP
      When I submit a '<ci_cri>' event
      Then I get a '<ci_cri>' CRI response
      When I submit '<ci_details>' details to the CRI stub
      Then I get a '<noMatchPage>' page response
      When I submit a 'next' event
      Then I get a '<mitigating_cri>' CRI response
      When I call the CRI stub and get a 'server_error' OAuth error
      Then I get a 'sorry-technical-problem' page response with context 'dlOrPassportMitigation'
      When I submit an 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

      Examples:
        | ci_cri            | ci_details                                 | noMatchPage                              | mitigating_cri |
        | ukPassport        | kenneth-passport-needs-alternate-doc       | pyi-passport-no-match-another-way        | drivingLicence |
        | drivingLicence    | kenneth-driving-permit-needs-alternate-doc | pyi-driving-licence-no-match-another-way | ukPassport     |

  Rule: Experian KBV
    Background: Route to sorry-technical-problem Experian KBV CRI error page
      Given  I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit a 'neither' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-multiple-doc-check' page response
      When I submit a 'ukPassport' event
      Then I get a 'ukPassport' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I call the CRI stub with attributes and get a 'server_error' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'sorry-technical-problem' page response with context 'kbvCriError'

    Scenario: Unexpected error from Experian KBV CRI - try CRI again
      When I submit a 'tryAgain' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: Unexpected error from Experian KBV CRI - try app route
      When I submit a 'app' event
      Then I get a 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
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
      Then I get a 'P2' identity

    Scenario: Unexpected error from Experian KBV CRI - try post office route
      When I submit a 'postOffice' event
      Then I get a 'f2f' CRI response
      When I submit 'kenneth-passport-valid' details with attributes to the async CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":0} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: Unexpected error from Experian KBV CRI - return to RP
      When I submit an 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

  Rule: F2F CRI - P2
    Background: Route to sorry-technical-problem F2F CRI error page
      Given I start a new 'medium-confidence' journey
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
      When I call the CRI stub with attributes and get a 'server_error' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'sorry-technical-problem' page response with context 'f2fCriError'

    Scenario: Unexpected error from F2F CRI - try CRI again
      When I submit a 'tryAgain' event
      Then I get a 'f2f' CRI response
      When I submit 'kenneth-passport-valid' details with attributes to the async CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: Unexpected error from F2F CRI - try app routeWhen I submit a 'app' event
      When I submit a 'app' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
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
      Then I get a 'P2' identity

    Scenario: Unexpected error from F2F CRI - try web route
      When I submit a 'webRoute' event
      Then I get a 'page-multiple-doc-check' page response
      When I submit a 'ukPassport' event
      Then I get a 'ukPassport' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: Unexpected error from F2F CRI - return to RP
      When I submit an 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

  Rule: F2F CRI - P1
    Background: Route to sorry-technical-problem F2F CRI error page
      Given I activate the 'p1Journeys' feature set
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit a 'neither' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-multiple-doc-check' page response with context 'nino'
      When I submit an 'end' event
      Then I get a 'pyi-post-office' page response
      When I submit a 'next' event
      Then I get a 'claimedIdentity' CRI response
        # Using a different name in the scenarios to check that the reset_session call after
        # the 'sorry-technical-problem' page happens
      When I submit 'lora' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'lora-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'lora-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'f2f' CRI response
      When I call the CRI stub with attributes and get a 'server_error' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get a 'sorry-technical-problem' page response with context 'f2fCriError'

    Scenario: Unexpected error from F2F CRI - try app route
      When I submit a 'app' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
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
      Then I get a 'P1' identity

    Scenario: Unexpected error from F2F CRI - try web route
      When I submit a 'webRoute' event
      Then I get a 'page-multiple-doc-check' page response with context 'nino'
      When I submit a 'ukPassport' event
      Then I get a 'ukPassport' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity

  Rule: F2F CRI mitigation via Experian KBV
    Background: Route to sorry-technical-problem F2F mitigation error page
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When I submit a 'preferNoApp' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-multiple-doc-check' page response
      When I submit a 'ukPassport' event
      Then I get a 'ukPassport' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'personal-independence-payment' page response
      When I submit a 'end' event
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'experianKbv' CRI response
      When I submit 'kenneth-needs-enhanced-verification' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'photo-id-security-questions-find-another-way' page response

    Scenario: Same session mitigation via F2F - return to RP
      When I submit a 'f2f' event
      Then I get a 'f2f' CRI response
      When I call the CRI stub with attributes and get a 'server_error' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":0} |
      Then I get a 'sorry-technical-problem' page response with context 'kbvMitigation'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

    Scenario: Same session mitigation via F2F - switch to app after error
      When I submit a 'f2f' event
      Then I get a 'f2f' CRI response
      When I call the CRI stub with attributes and get a 'server_error' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":0} |
      Then I get a 'sorry-technical-problem' page response with context 'kbvMitigation'
      When I submit a 'app' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: Separate session F2F enhanced verification mitigation - user fails KBV - mitigate via F2F
      # Return journey
      When I start new 'medium-confidence' journeys until I get a 'page-ipv-identity-document-start' page response
      And I submit an 'end' event
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
      Then I get an 'f2f' CRI response
      When I call the CRI stub with attributes and get a 'server_error' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'sorry-technical-problem' page response with context 'kbvMitigation'
      When I submit a 'app' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
