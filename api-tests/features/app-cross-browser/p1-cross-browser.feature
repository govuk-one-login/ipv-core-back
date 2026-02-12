@Build @InitialisesDCMAWSessionState @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: P1 V2 App Cross Browser Scenario
  Rule: New identity proving journey - no mitigations
    Background: Start journey
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event

    Scenario Outline: MAM journey cross-browser scenario happy path - <device>
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an '<device>' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context '<device>'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
        # And the user returns from the app to core-front
      And I pass on the DCMAW callback in a separate session
      Then I get a 'problem-different-browser' page response
        # This simulates the user clicking continue on the problem-different-browser
        # page which sends a 'build-client-oauth-response' event to the journey engine
      When I submit a 'build-client-oauth-response' event in a separate session
      Then I get an OAuth response with error code 'access_denied'
        # Wait for the VC to be received before continuing. In the usual case the VC will be received well before the user
        # has managed to log back in to the site.
      When I poll for async DCMAW credential receipt
      And I start a new 'low-confidence' journey
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

      Examples:
      | device  |
      | iphone  |
      | android |

    Scenario: Cross-browser DL auth source check
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback in a separate session
      Then I get a 'problem-different-browser' page response
        # This simulates the user clicking continue on the problem-different-browser
        # page which sends a 'build-client-oauth-response' event to the journey engine
      When I submit a 'build-client-oauth-response' event in a separate session
      Then I get an OAuth response with error code 'access_denied'
      # Wait for the VC to be received before continuing. In the usual case the VC will be received well before the user
      # has managed to log back in to the site.
      When I poll for async DCMAW credential receipt
      And I start a new 'low-confidence' journey
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity

    Scenario: MAM journey cross-browser scenario unsuccessful VC without CI
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kenneth-passport-fail-no-ci' VC
        # And the user returns from the app to core-front
      And I pass on the DCMAW callback in a separate session
      Then I get a 'problem-different-browser' page response
        # This simulates the user clicking continue on the problem-different-browser
        # page which sends a 'build-client-oauth-response' event to the journey engine
      When I submit a 'build-client-oauth-response' event in a separate session
      Then I get an OAuth response with error code 'access_denied'
        # Wait for the VC to be received before continuing. In the usual case the VC will be received well before the user
        # has managed to log back in to the site.
      When I poll for async DCMAW credential receipt
      And I start a new 'low-confidence' journey
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

    Scenario: MAM journey cross-browser scenario unsuccessful VC with CI
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kenneth-driving-permit-with-breaching-ci' VC
        # And the user returns from the app to core-front
      And I pass on the DCMAW callback in a separate session
      Then I get a 'problem-different-browser' page response
        # This simulates the user clicking continue on the problem-different-browser
        # page which sends a 'build-client-oauth-response' event to the journey engine
      When I submit a 'build-client-oauth-response' event in a separate session
      Then I get an OAuth response with error code 'access_denied'
        # Wait for the VC to be received before continuing. In the usual case the VC will be received well before the user
        # has managed to log back in to the site.
      When I poll for async DCMAW credential receipt
      And I start a new 'low-confidence' journey
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

  Rule: Cross-browser during separate-session enhanced verification mitigation
    Background: Start separate-session enhanced verification mitigation
      Given I activate the 'drivingLicenceAuthCheck' feature set
      And the subject already has the following credentials
        | CRI         | scenario                            |
        | ukPassport  | kenneth-passport-valid              |
        | address     | kenneth-current                     |
        | fraud       | kenneth-score-2                     |
        | experianKbv | kenneth-needs-enhanced-verification |

      # Separate session mitigation
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'

    Scenario: Successful mitigation with DL auth source check
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC that mitigates the 'NEEDS-ENHANCED-VERIFICATION' CI
        # And the user returns from the app to core-front
      And I pass on the DCMAW callback in a separate session
      Then I get a 'problem-different-browser' page response
        # This simulates the user clicking continue on the problem-different-browser
        # page which sends a 'build-client-oauth-response' event to the journey engine
      When I submit a 'build-client-oauth-response' event in a separate session
      Then I get an OAuth response with error code 'access_denied'
        # Wait for the VC to be received before continuing. In the usual case the VC will be received well before the user
        # has managed to log back in to the site.
      When I poll for async DCMAW credential receipt
      And I start a new 'low-confidence' journey
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                   |
        | evidence_requested | {"identityFraudScore":2} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity

    Scenario: Separate session DCMAW enhanced verification mitigation - user fails DCMAW with no ci (e.g. failed likeness) - mitigate via F2F
      When the async DCMAW CRI produces a 'kenneth-passport-fail-no-ci' VC
      And I pass on the DCMAW callback in a separate session
      Then I get a 'problem-different-browser' page response
      # This simulates the user clicking continue on the problem-different-browser
      # page which sends a 'build-client-oauth-response' event to the journey engine
      When I submit a 'build-client-oauth-response' event in a separate session
      Then I get an OAuth response with error code 'access_denied'
      # Wait for the VC to be received before continuing. In the usual case the VC will be received well before the user
      # has managed to log back in to the site.
      When I poll for async DCMAW credential receipt
      And I start a new 'low-confidence' journey
      Then I get a 'pyi-post-office' page response

    Scenario: Separate session DCMAW enhanced verification mitigation - breaching CI received from DCMAW
      When the async DCMAW CRI produces a 'kennethD' 'drivingPermit' 'fail' VC with a CI
      And I pass on the DCMAW callback in a separate session
      Then I get a 'problem-different-browser' page response
      # This simulates the user clicking continue on the problem-different-browser
      # page which sends a 'build-client-oauth-response' event to the journey engine
      When I submit a 'build-client-oauth-response' event in a separate session
      Then I get an OAuth response with error code 'access_denied'
      # Wait for the VC to be received before continuing. In the usual case the VC will be received well before the user
      # has managed to log back in to the site.
      When I poll for async DCMAW credential receipt
      And I start a new 'low-confidence' journey
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

    Scenario: Separate session DCMAW enhanced verification mitigation - DL auth check acquires CI
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC that mitigates the 'NEEDS-ENHANCED-VERIFICATION' CI
      And I pass on the DCMAW callback in a separate session
      Then I get a 'problem-different-browser' page response
      # This simulates the user clicking continue on the problem-different-browser
      # page which sends a 'build-client-oauth-response' event to the journey engine
      When I submit a 'build-client-oauth-response' event in a separate session
      Then I get an OAuth response with error code 'access_denied'
      # Wait for the VC to be received before continuing. In the usual case the VC will be received well before the user
      # has managed to log back in to the site.
      When I poll for async DCMAW credential receipt
      And I start a new 'low-confidence' journey
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-needs-alternate-doc' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

    Scenario: Separate session DCMAW enhanced verification mitigation - DL auth check incomplete
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC that mitigates the 'NEEDS-ENHANCED-VERIFICATION' CI
      And I pass on the DCMAW callback in a separate session
      Then I get a 'problem-different-browser' page response
      # This simulates the user clicking continue on the problem-different-browser
      # page which sends a 'build-client-oauth-response' event to the journey engine
      When I submit a 'build-client-oauth-response' event in a separate session
      Then I get an OAuth response with error code 'access_denied'
      # Wait for the VC to be received before continuing. In the usual case the VC will be received well before the user
      # has managed to log back in to the site.
      When I poll for async DCMAW credential receipt
      And I start a new 'low-confidence' journey
      Then I get a 'drivingLicence' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
      When I submit a 'next' event

      # Attempt 2 - retry after viewing prove-identity-another-way
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
      And I pass on the DCMAW callback in a separate session
      Then I get a 'problem-different-browser' page response
      # This simulates the user clicking continue on the problem-different-browser
      # page which sends a 'build-client-oauth-response' event to the journey engine
      When I submit a 'build-client-oauth-response' event in a separate session
      Then I get an OAuth response with error code 'access_denied'
      # Wait for the VC to be received before continuing. In the usual case the VC will be received well before the user
      # has managed to log back in to the site.
      When I poll for async DCMAW credential receipt
      And I start a new 'low-confidence' journey
      Then I get a 'drivingLicence' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
      When I submit an 'end' event
      Then I get a 'prove-identity-another-way' page response
      When I submit an 'anotherTypePhotoId' event

      # Attempt 3 - give up
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
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
      When I submit an 'end' event
      Then I get a 'prove-identity-another-way' page response
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
