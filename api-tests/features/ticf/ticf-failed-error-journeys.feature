@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: TICF failed/error journeys
  Rule: Via enhanced-verification journey
    Background: Start TICF enhanced verification journey
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

    Scenario: TICF failed enhanced-verification journey - PYI_NO_MATCH
      When I submit a 'appTriage' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC with a CI
    # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |

    Scenario: TICF failed enhanced-verification journey - PYI_ANOTHER_WAY
      When I submit a 'appTriage' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit a 'neither' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'pyi-post-office' page response
      When I submit a 'end' event
      Then I get a 'pyi-another-way' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |

    Scenario: TICF failed enhanced-verification journey - PYI_TECHNICAL
      When I submit an 'f2f' event
      Then I get a 'f2f' CRI response
      When I call the CRI stub with attributes and get a 'temporarily_unavailable' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":0} |
      Then I get a 'pyi-technical' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |

  Rule: Via post-office
    Scenario: TICF failed post-office journey - PYI_ESCAPE
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'end' event
      Then I get a 'no-photo-id-exit-find-another-way' page response
      When I submit an 'end' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |

  Rule: Via no-photo-id
    Scenario: TICF failed M2B journey - PYI_ESCAPE_M2B
      Given I activate the 'm2bBetaExperianKbv' feature set
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
      When I submit an 'end' event
      Then I get a 'pyi-post-office' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response
      When I submit an 'end' event
      Then I get a 'no-photo-id-exit-find-another-way' page response
      When I submit an 'end' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |
