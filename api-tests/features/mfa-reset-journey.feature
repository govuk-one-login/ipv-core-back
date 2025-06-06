@Build
Feature: MFA reset journey
  Rule: User has an existing identity
    Background: There is an existing user and they start an MFA reset journey
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |

      # Start MFA reset journey
      And I activate the 'disableStrategicApp' feature set
      When I start a new 'reverification' journey
      Then I get a 'you-can-change-security-code-method' page response

    Scenario: Successful MFA reset journey
      When I submit a 'next' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get a 'we-matched-you-to-your-one-login' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get a successful MFA reset result

    Scenario: Successful MFA reset journey - with DL auth source check
      When I submit a 'next' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'we-matched-you-to-your-one-login' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an successful MFA reset result

    Scenario: Failed MFA reset journey with breaching CI - user can still reuse existing identity
      When I submit a 'next' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-with-breaching-ci' details to the CRI stub
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_check_failed'

      # New journey with same user id
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-reuse' page response

    Scenario: Failed MFA reset journey - DCMAW error
      When I submit a 'next' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_check_incomplete'

    Scenario: Failed MFA reset journey - find another way to access One Login
      When I submit an 'cannot-change-security-codes' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_check_incomplete'

    Scenario: Failed MFA reset journey - failed verification score
      When I submit a 'next' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-verification-zero' details to the CRI stub
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_check_failed'

    Scenario: Failed MFA reset journey - non-matching identity
      When I submit a 'next' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'alice-passport-valid' details to the CRI stub
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_did_not_match'

    Scenario: Failed MFA reset journey - failed DL auth source check
      When I submit a 'next' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-needs-alternate-doc' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_check_failed'

    Scenario: Failed MFA reset journey - incorrect DL details from DL auth source check - prove identity another way
      When I submit a 'next' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I call the CRI stub with attributes and get an 'access_denied' OAuth error
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'uk-driving-licence-details-not-correct' page response
      When I submit a 'end' event
      Then I get a 'prove-identity-another-way' page response with context 'noF2f'
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_check_incomplete'

    Scenario: Incorrect DL details from DL auth source check - allowed retry through the app
      When I submit a 'next' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I call the CRI stub with attributes and get an 'access_denied' OAuth error
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'uk-driving-licence-details-not-correct' page response
      When I submit a 'next' event
      Then I get a 'dcmaw' CRI response

  Rule: User has an existing identity and uses the strategic app
    Background:
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      And I activate the 'strategicApp,drivingLicenceAuthCheck' feature set

      # Start MFA reset journey
      When I start a new 'reverification' journey
      Then I get a 'you-can-change-security-code-method' page response
      When I submit a 'next' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'

    @InitialisesDCMAWSessionState
    Scenario: MAM, abandon
      When I submit an 'anotherWay' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_check_incomplete'

    @InitialisesDCMAWSessionState
    Scenario: MAM, successful
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'we-matched-you-to-your-one-login' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get a successful MFA reset result

    @InitialisesDCMAWSessionState
    Scenario: MAM, incomplete DL auth check
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
      Then I get a 'prove-identity-another-way' page response with context 'noF2f'

      # User gives up
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_check_incomplete'

    @InitialisesDCMAWSessionState
    Scenario: MAM, retry from incomplete DL auth check
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
      Then I get a 'prove-identity-another-way' page response with context 'noF2f'

      # User trys again
      When I submit an 'anotherTypePhotoId' event
      Then I get a 'identify-device' page response
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
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'we-matched-you-to-your-one-login' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get a successful MFA reset result

    @InitialisesDCMAWSessionState
    Scenario: MAM, alternate doc failure
      When the async DCMAW CRI produces a 'kenneth-driving-permit-valid' VC
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-needs-alternate-doc' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_check_failed'

  Rule: The user has no existing identity
    Scenario: Attempted MFA reset journey
      When I start a new 'reverification' journey
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'no_identity_available'
