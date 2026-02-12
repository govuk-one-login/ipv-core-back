@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Return exit codes
  Scenario: Successful journey with identity and no CIs - no return codes
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
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
    And I don't get any return codes

  Scenario: Failed identity journey with no CI - user doesn't hold appropriate documents - non-ci-breaching code returned
    Given I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'page-ipv-identity-postoffice-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response
    When I submit a 'end' event
    Then I get a 'no-photo-id-exit-find-another-way' page response
    When I submit a 'end' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
    And I get 'non-ci-breaching' return code

  Scenario: KBV score zero and failure to complete journey - non-ci-breaching code returned
    Given I start a new 'medium-confidence' journey
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
    When I submit a 'drivingLicence' event
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
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
    When I submit 'kenneth-score-0' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'photo-id-security-questions-find-another-way' page response with context 'dropout'
    When I submit a 'f2f' event
    Then I get a 'f2f' CRI response
    When I call the CRI stub with attributes and get an 'access_denied' OAuth error
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":0} |
    Then I get a 'pyi-another-way' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
    And I get 'non-ci-breaching' return code

  Scenario: CI mitigated in separate session but failed to complete journey - non-ci-breaching code returned
    Given the subject already has the following credentials
      | CRI              | scenario                            |
      | drivingLicence   | kenneth-driving-permit-valid        |
      | address          | kenneth-current                     |
      | fraud            | kenneth-score-2                     |
      | experianKbv      | kenneth-needs-enhanced-verification |

    # Start new session
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
    When the async DCMAW CRI produces a 'kenneth-passport-valid' VC that mitigates the 'NEEDS-ENHANCED-VERIFICATION' CI
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I call the CRI stub and get a 'temporarily_unavailable' OAuth error
    Then I get a 'pyi-technical' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
    And I get 'non-ci-breaching' return code

  Scenario: Successful journey with always-required return code - always-required code returned
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
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
    When I submit 'kenneth-score-2-always-required' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And I get 'always-required' return code

  Scenario: Breaching CI codes generate return codes, including mitigated CIs - CI codes returned
    When I start a new 'medium-confidence' journey
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
    When I submit 'kenneth-score-2-non-breaching' details with attributes to the CRI stub
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
    When I submit an 'f2f' event
    Then I get a 'f2f' CRI response
    When I call the CRI stub with attributes and get an 'access_denied' OAuth error
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":0} |
    Then I get a 'pyi-another-way' page response
    When I submit an 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
    And I get 'non-breaching,needs-enhanced-verification' return codes

    # New journey with the same user id
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
    When the async DCMAW CRI produces a 'kenneth-passport-valid' VC that mitigates the 'NEEDS-ENHANCED-VERIFICATION' CI
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
    When I submit 'kenneth-score-0-breaching' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'pyi-no-match' page response
    When I submit an 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
    And I get 'non-breaching,breaching,needs-enhanced-verification' return codes

  Scenario: Breaching CI code generates return code
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
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
    When I submit 'kenneth-score-0-breaching' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'pyi-no-match' page response
    When I submit an 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
    And I get 'breaching' return codes
