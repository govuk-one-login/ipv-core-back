@Build # TODO: add ticf env variables to build (see run-tests.sh)
Feature: TICF journey
  Scenario: TICF API request - with no CI same session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    # TODO: assert against TICF VC
    Then I get a 'P2' identity

  Scenario: TICF API request - with no CI in separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    # New journey
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-reuse' page response
    And my proven user details match
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: TICF API request - with no CI initially and then a CI in a separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    # New journey
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | cis           | BREACHING                    |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'pyi-no-match' page response

  Scenario: TICF API request - with no CI initially then timeout in separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    # New journey
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | timeOut                      |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-reuse' page response
    And my proven user details match
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: TICF API request - with CI same session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | cis           | BREACHING                    |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'pyi-no-match' page response

  Scenario: TICF API request - with CI separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | cis           | BREACHING                    |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'pyi-no-match' page response

    # New journey
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'pyi-no-match' page response

  Scenario: TICF API request - with CI initially then no CI in separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | cis           | BREACHING                    |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'pyi-no-match' page response

    # New journey
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'pyi-no-match' page response

  Scenario: TICF API request - for timeout and no CI in separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | timeOut                      |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    # New journey
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-reuse' page response
    And my proven user details match
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: TICF API request - for timeout then CI in separate session
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | txn           | timeOut                      |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    # New journey
    Given there is an existing TICF record for the user with details
      | responseDelay | 0                            |
      | type          | RiskAssessment               |
      | cis           | BREACHING                    |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'pyi-no-match' page response

  Scenario: TICF API request - response delay less than 5s
    Given there is an existing TICF record for the user with details
      | responseDelay | 4                            |
      | type          | RiskAssessment               |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    # TODO: assert against TICF VC
    Then I get a 'P2' identity

  Scenario: TICF API request - response delay more than 5s
    Given there is an existing TICF record for the user with details
      | responseDelay | 6                            |
      | type          | RiskAssessment               |
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    When I start a new 'medium-confidence' journey with feature set 'ticfCriBeta'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    # TODO: assert against TICF VC (we expect now TICF VC here)
    Then I get a 'P2' identity

  Scenario: TICF API request - F2F separate session check
    Given there is an existing TICF record for the user with details
      | responseDelay | 6                            |
      | type          | RiskAssessment               |
    Given I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'page-ipv-identity-postoffice-start' page response
    When I submit a 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-passport-valid' details to the async CRI stub
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    # TODO: assert against TICF VC
    Then I get a 'P2' identity
