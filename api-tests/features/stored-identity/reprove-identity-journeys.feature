@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Reprove Identity Journey
  Background:
    Given I activate the 'storedIdentityService' feature set

  Rule: P2 Journeys
    Background:
      Given the subject already has the following credentials
        | CRI     | scenario               |
        | dcmaw   | kenneth-passport-valid |
        | address | kenneth-current        |
        | fraud   | kenneth-score-2        |
      And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
      When I start a new 'medium-confidence' journey
      Then I get a 'reprove-identity-start' page response
      When I submit a 'next' event
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response

    Scenario: User reproves identity
      When I submit an 'appTriage' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit an 'android' event
      Then I get a 'pyi-triage-desktop-download-app' page response with context 'android'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
      And I poll for async DCMAW credential receipt
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
      And I have a GPG45 stored identity record type with a 'P3' vot

    Scenario: User reproves with F2F
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
      When I submit 'kenneth-driving-permit-valid' details with attributes to the async CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey after popping out to the Post Office
      Given The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
      When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
      And I have a GPG45 stored identity record type with a 'P2' vot

  Rule: P1 Journeys
    Background:
      Given the subject already has the following credentials with overridden document expiry date
        | CRI     | scenario                     | documentType  |
        | dcmaw   | kenneth-driving-permit-valid | drivingPermit |
      And the subject already has the following credentials
        | CRI     | scenario                     |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
      When I start a new 'low-confidence' journey
      Then I get a 'reprove-identity-start' page response
      When I submit a 'next' event
      Then I get a 'page-ipv-identity-document-start' page response

    Scenario: User reproves identity
      When I submit an 'appTriage' event
      Then I get an 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit an 'android' event
      Then I get a 'pyi-triage-desktop-download-app' page response with context 'android'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
      And I poll for async DCMAW credential receipt
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
      And I have a GPG45 stored identity record type with a 'P3' vot

    Scenario: User reproves with F2F
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
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
      When I submit 'kenneth-passport-valid' details with attributes to the async CRI stub
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new 'low-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And I have a GPG45 stored identity record type with a 'P2' vot
