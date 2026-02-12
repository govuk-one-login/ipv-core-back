@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: MFA reset journey
  Rule: User has an existing identity
    Background: There is an existing user and they start an MFA reset journey
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |

      # Start MFA reset journey
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

  Rule: User has an existing identity and strategic app is enabled
    Background: There is an existing user and they start an MFA reset journey
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      # Even when the v2 app is enabled the reverification journey should use the v1 app as the user won't be
      # able to log in to the v2 app to use it.
      And I activate the 'strategicApp' feature set

      # Start MFA reset journey
      When I start a new 'reverification' journey
      Then I get a 'you-can-change-security-code-method' page response

    Scenario: Successful MFA reset journey still using v1 app
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

  Rule: The user has no existing identity
    Scenario: Attempted MFA reset journey
      When I start a new 'reverification' journey
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'no_identity_available'

  Scenario: Successful MFA reset journey ignores AIS
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |

      # Start MFA reset journey
      When I start a new 'reverification' journey
      Then I get a 'you-can-change-security-code-method' page response
      When I submit a 'next' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When The AIS stub will return an 'AIS_ACCOUNT_BLOCKED' result
      And I submit 'kenneth-passport-valid' details to the CRI stub
      Then I get a 'we-matched-you-to-your-one-login' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get a successful MFA reset result
