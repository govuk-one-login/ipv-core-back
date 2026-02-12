@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Update name journey with DL auth source check
  Background: User has existing credentials and starts an update details journey
    Given I activate the 'drivingLicenceAuthCheck' feature sets
      And the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-passport-valid       |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit a 'update-details' event
      Then I get a 'update-details' page response

  Scenario Outline: Successful name change - <selected-name-change> name change but user updates <actual-name-change> name instead
    When I submit a '<selected-name-change>' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit an 'android' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly'
    When the async DCMAW CRI produces a '<details>' VC
    And I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response
    When I submit '<details>' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit '<fraud-details>' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'page-ipv-success' page response with context 'updateIdentity'
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And my identity 'GivenName' is '<expected-given-name>'
    And my identity 'FamilyName' is '<expected-family-name>'

    Examples:
      | selected-name-change | actual-name-change | details                                          | fraud-details                       | expected-given-name | expected-family-name |
      | given-names-only     | family             | kenneth-changed-family-name-driving-permit-valid | kenneth-changed-family-name-score-2 | Kenneth             | Smith                |
      | family-name-only     | given              | kenneth-changed-given-name-driving-permit-valid  | kenneth-changed-given-name-score-2  | Ken                 | Decerqueira          |

  Scenario Outline: Address and Name Change - successful
    When I submit a '<selected-name-change>' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit an 'android' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context 'android-appOnly'
    When the async DCMAW CRI produces a '<details>' VC
    And I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response
    When I submit '<details>' details with attributes to the CRI stub
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
    When I submit a 'next' event
    Then I get a 'address' CRI response
    When I submit 'kenneth-changed' details with attributes to the CRI stub
      | Attribute | Values               |
      | context   | "international_user" |
    Then I get a 'fraud' CRI response
    When I submit '<fraud-details>' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'page-ipv-success' page response with context 'updateIdentity'
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And my identity 'GivenName' is '<expected-given-name>'
    And my identity 'FamilyName' is '<expected-family-name>'
    And my address 'addressLocality' is 'Bristol'

    Examples:
      | selected-name-change    | details                                          | fraud-details                       | expected-given-name | expected-family-name |
      | family-name-and-address | kenneth-changed-family-name-driving-permit-valid | kenneth-changed-family-name-score-2 | Kenneth             | Smith                |
      | given-names-and-address | kenneth-changed-given-name-driving-permit-valid  | kenneth-changed-given-name-score-2  | Ken                 | Decerqueira          |

  Scenario: Change of name only journey - User backs out of DL CRI - Returns to DCMAW to use passport
    When I submit a 'given-names-only' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
    When the async DCMAW CRI produces a 'kenneth-changed-given-name-driving-permit-valid' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub with attributes and get an 'access_denied' OAuth error
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
    When I submit a 'next' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
    When the async DCMAW CRI produces a 'kenneth-changed-given-name-passport-valid' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'page-dcmaw-success' page response with context 'coiNoAddress'
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-given-name-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'updateIdentity'
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And I have a dcmawAsync VC without 'drivingPermit' details

  Scenario: Change of name and address journey - User backs out of DL CRI - Returns to DCMAW to use passport
    When I submit a 'family-name-and-address' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
    When the async DCMAW CRI produces a 'kenneth-changed-family-name-driving-permit-valid' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub with attributes and get an 'access_denied' OAuth error
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
    When I submit a 'next' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
    When the async DCMAW CRI produces a 'kenneth-changed-family-name-passport-valid' VC
  # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'page-dcmaw-success' page response with context 'coiAddress'
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-changed' details with attributes to the CRI stub
      | Attribute | Values               |
      | context   | "international_user" |
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-changed-family-name-and-address-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'updateIdentity'
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And I have a dcmawAsync VC without 'drivingPermit' details

  Scenario Outline: Change of details - dropout DL auth source check - return to RP with no identity
    When I submit a '<update-type>' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
    When the async DCMAW CRI produces a 'kenneth-changed-given-name-driving-permit-valid' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub with attributes and get an 'access_denied' OAuth error
      | Attribute | Values          |
      | context   | "check_details" |
    Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
    When I submit an 'end' event
    Then I get a 'prove-identity-another-way' page response with context 'noF2f'
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

    Examples:
      | update-type             |
      | given-names-only        |
      | given-names-and-address |

  Scenario Outline: Change with incorrect DL details retries then gives up
    When I submit a '<change-type>' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event

    # Attempt 1 - retry at first opportunity
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
    When the async DCMAW CRI produces a 'kenneth-changed-family-name-driving-permit-valid' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
    Then I get a 'drivingLicence' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'uk-driving-licence-details-not-correct' page response with context 'strategicApp'
    When I submit a 'next' event

    # Attempt 2 - retry after viewing prove-identity-another-way
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
    When the async DCMAW CRI produces a 'kenneth-changed-family-name-driving-permit-valid' VC
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
    When I submit an 'anotherTypePhotoId' event

    # Attempt 3 - give up
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
    When the async DCMAW CRI produces a 'kenneth-changed-family-name-driving-permit-valid' VC
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
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

    Examples:
      | change-type             |
      | given-names-only        |
      | family-name-and-address |

  Scenario Outline: New driving licence is invalid
    When I submit a '<change-type>' event
    Then I get a 'page-update-name' page response
    When I submit a 'update-name' event

    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone-appOnly'
    When the async DCMAW CRI produces a 'kenneth-changed-family-name-driving-permit-valid' VC
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
    Then I get an 'sorry-could-not-confirm-details' page response with context 'existingIdentityInvalid'
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

    Examples:
      | change-type             |
      | given-names-only        |
      | family-name-and-address |
