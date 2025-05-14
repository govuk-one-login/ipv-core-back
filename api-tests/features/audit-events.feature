Feature: Audit Events
  Scenario: New identity - p2 app journey
    And I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
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
    And audit events for 'new-identity-p2-app-journey' are recorded [local only]

  Scenario: Reuse journey
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And audit events for 'reuse-journey' are recorded [local only]

  Scenario: New identity - via F2F journey
    And I start a new 'medium-confidence' journey
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
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-driving-permit-valid' details with attributes to the async CRI stub
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    # We want to wait a suitable period of time to let the request to the process-async-cri lambda to finish before
    # starting a new session. This will hopefully reduce flakiness with this test where we expect the
    # events to be in a certain order.
    When I wait for 3 seconds for the async credential to be processed
    And I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
    And I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And audit events for 'new-identity-f2f-journey' are recorded [local only]

  Scenario: Delete pending F2F
    And I start a new 'medium-confidence' journey
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
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
    Then I get a 'page-face-to-face-handoff' page response

    Given I activate the 'pendingF2FResetEnabled' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-pending' page response with context 'f2f-delete-details'
    When I submit a 'next' event
    Then I get a 'pyi-f2f-delete-details' page response
    When I submit a 'next' event
    Then I get a 'pyi-confirm-delete-details' page response with context 'f2f'
    When I submit a 'next' event
    Then I get a 'pyi-details-deleted' page response with context 'f2f'
    And audit events for 'delete-pending-f2f-journey' are recorded [local only]

  Scenario: Alternate doc mitigation
    And I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response
    When I submit an 'drivingLicence' event
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-needs-alternate-doc' details to the CRI stub
    Then I get a 'pyi-driving-licence-no-match-another-way' page response
    When I submit a 'next' event
    Then I get a 'ukPassport' CRI response
    And audit events for 'alternate-doc-mitigation-journey' are recorded [local only]

  Scenario: Reprove identity journey
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And I start a new 'medium-confidence' journey with reprove identity
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
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
    And audit events for 'reprove-identity-journey' are recorded [local only]

  Scenario: Reprove identity journey with AIS
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    And The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
    When I activate the 'accountInterventions' feature set
    And I start a new 'medium-confidence' journey
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
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
    And audit events for 'reprove-identity-journey' are recorded [local only]

  Scenario: No photo ID
    Given I activate the 'p1Journeys' feature set
    When I start a new 'low-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
    When I submit an 'next' event
    Then I get a 'claimedIdentity' CRI response
    And audit events for 'no-photo-id-journey' are recorded [local only]

  Scenario: Update name and address journey
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'update-details' event
    Then I get a 'update-details' page response

    # End update journey to ensure recording of IPV_USER_DETAILS_UPDATE_ABORTED event
    When I submit an 'cancel' event
    Then I get an OAuth response

    # Start another journey to start and complete update journey
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-reuse' page response
    When I submit a 'update-details' event
    Then I get a 'update-details' page response
    When I submit a 'family-name-and-address' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-changed-family-name-driving-permit-valid' details to the CRI stub
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-changed-family-name-driving-permit-valid' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
    When I submit a 'next' event
    Then I get a 'address' CRI response
    When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-family-name-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response with context 'updateIdentity'
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And audit events for 'update-name-and-address-journey' are recorded [local only]

  Scenario: Inherited identity journey
    And I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl200-no-evidence'
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'PCL200' identity
    And audit events for 'inherited-identity-journey' are recorded [local only]

  Scenario: International address journey
    And I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'international' event
    Then I get a 'non-uk-app-intro' page response
    When I submit a 'useApp' event
    Then I get a 'dcmaw' CRI response
    And audit events for 'international-address-journey' are recorded [local only]

  Scenario: Strategic app journey
    Given I activate the 'strategicApp' feature set
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
    And audit events for 'strategic-app-journey' are recorded [local only]

  @InitialisesDCMAWSessionState
  Scenario: MAM journey cross-browser scenario
    Given I activate the 'strategicApp' feature set
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
    When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback in a separate session
    Then I get an error response with message 'Missing ipv session id header' and status code '400'
    # Wait for the VC to be received before continuing. In the usual case the VC will be received well before the user
    # has managed to log back in to the site.
    When I poll for async DCMAW credential receipt
    And I start a new 'medium-confidence' journey
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
    And audit events for 'strategic-app-cross-browser-journey' are recorded [local only]

  Scenario: Reverification - failed journey
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
      | fraud   | kenneth-score-2              |
    When I start a new 'reverification' journey
    Then I get a 'you-can-change-security-code-method' page response
    When I submit a 'next' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-with-breaching-ci' details to the CRI stub
    Then I get an OAuth response
    When I use the OAuth response to get my MFA reset result
    Then I get an unsuccessful MFA reset result with failure code 'identity_check_failed'
    And audit events for 'reverification-failed-journey' are recorded [local only]

  Rule: DWP KBV
    Background: Start a journey to DWP KBV CRI
      Given I activate the 'dwpKbvTest' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'page-multiple-doc-check' page response
      When I submit a 'drivingLicence' event
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'personal-independence-payment' page response
      When I submit a 'next' event
      Then I get a 'page-pre-dwp-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'dwpKbv' CRI response

    Scenario: DWP KBV - successful response
      When I submit 'kenneth-score-2' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-ipv-success' page response
      And audit events for 'dwp-kbv-successful-journey' are recorded [local only]

    Scenario: DWP KBV - dropout via thin file
      When I call the CRI stub with attributes and get an 'invalid_request' OAuth error
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-different-security-questions' page response
      And audit events for 'dwp-kbv-dropout-via-thin-file' are recorded [local only]

    Scenario: DWP KBV - user abandons CRI
      When I call the CRI stub with attributes and get an 'access_denied' OAuth error with error description 'user_abandoned'
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
      Then I get a 'page-pre-experian-kbv-transition' page response
      And audit events for 'dwp-kbv-dropout-user-abandons-cri' are recorded [local only]
