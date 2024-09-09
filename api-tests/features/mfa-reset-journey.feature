Feature: MFA reset journey
  Background: There is an existing user and they start an MFA reset journey
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |

    # Start MFA reset journey
    When I start a new 'reverification' journey
    Then I get a 'page-ipv-identity-document-start' page response

  @Build
  Scenario: Successful MFA reset journey
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my MFA reset result
    Then I get a successful MFA reset result

  Scenario: Successful MFA reset journey - with CI
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-needs-enhanced-verification' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my MFA reset result
    Then I get a successful MFA reset result

  @Build
  Scenario: Failed MFA reset journey - DCMAW error
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access-denied' OAuth error from the CRI stub
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my MFA reset result
    Then I get an unsuccessful MFA reset result

  @Build
  Scenario: Failed MFA reset journey - no photo id
    When I submit an 'end' event
    Then I get a 'pyi-another-way' page response
    When I submit an 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my MFA reset result
    Then I get an unsuccessful MFA reset result

  @Build
  Scenario: Failed MFA reset journey - failed verification score
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-invalid-verification-zero' details to the CRI stub
    Then I get a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my MFA reset result
    Then I get an unsuccessful MFA reset result

  @Build
  Scenario: Failed MFA reset journey - non-matching identity
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'alice-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get a 'sorry-could-not-confirm-details' page response
    When I submit a 'end' event
    Then I get an OAuth response
    When I use the OAuth response to get my MFA reset result
    Then I get an unsuccessful MFA reset result
