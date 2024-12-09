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
      When I start a new 'reverification' journey
      Then I get a 'page-ipv-identity-document-start' page response

    Scenario: Successful MFA reset journey
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get a successful MFA reset result

    Scenario: Failed MFA reset journey with breaching CI - user can still reuse existing identity
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-with-breaching-ci' details to the CRI stub
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_check_failed'

      # New journey with same user id
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-reuse' page response

    Scenario: Failed MFA reset journey - DCMAW error
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access-denied' OAuth error
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_check_incomplete'

    Scenario: Failed MFA reset journey - no photo id
      When I submit an 'end' event
      Then I get a 'pyi-another-way' page response
      When I submit an 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_check_incomplete'

    Scenario: Failed MFA reset journey - failed verification score
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-verification-zero' details to the CRI stub
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_check_failed'

    Scenario: Failed MFA reset journey - non-matching identity
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'alice-passport-valid' details to the CRI stub
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'identity_did_not_match'

  Rule: The user has no existing identity
    Scenario: Attempted MFA reset journey
      When I start a new 'reverification' journey
      Then I get an OAuth response
      When I use the OAuth response to get my MFA reset result
      Then I get an unsuccessful MFA reset result with failure code 'no_identity_available'
