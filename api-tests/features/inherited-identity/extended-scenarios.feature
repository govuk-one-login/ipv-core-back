@Build
Feature: Inherited identity extended scenarios
  Background: Disable the strategic app
    Given I activate the 'disableStrategicApp' feature set

  Scenario: Successful enhanced verification mitigation with a PCL250 HMRC profile and receives a P2
    Given I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
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
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-needs-enhanced-verification' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'photo-id-security-questions-find-another-way' page response

    # New journey with inherited identity - user still needs to mitigate the CI
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'kenneth-vot-pcl250-passport'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'pyi-post-office' page response
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
    When I submit 'kenneth-driving-permit-valid' details with attributes to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: Fails to migrate PCL250 HMRC profile when user fails with breaching CI
    Given I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-with-breaching-ci' details to the CRI stub
    Then I get an 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

    # New journey with inherited identity for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'kenneth-vot-pcl250-passport'
    Then I get a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

  Scenario: Successfully migrates PCL250 HMRC profile for user with pending F2F
    Given I start a new 'medium-confidence' journey
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
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-passport-breaching' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
    Then I get a 'page-face-to-face-handoff' page response
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-pending' page response

    # Return journey with inherited identity for the same user
    When I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'kenneth-vot-pcl250-passport'
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity

  Scenario: Successfully migrates PCL250 HMRC profile when user has failed F2F (no CI)
    Given I start a new 'medium-confidence' journey
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
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'f2f' CRI response
    When I get an error from the async CRI stub
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    When I start new 'medium-confidence' journeys until I get a 'pyi-f2f-technical' page response
    When I submit a 'end' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity without a TICF VC

    # New journey with inherited identity for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'kenneth-vot-pcl250-passport'
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity

  Scenario: Successfully completes reprove identity journey with a PCL250 HMRC profile and receives a P2
    # Start reprove identity journey with inherited identity after incomplete P2
    Given The AIS stub will return an 'AIS_FORCED_USER_IDENTITY_VERIFY' result
    And I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'kenneth-vot-pcl250-passport'
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
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
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: Successfully completes a 6MFC journey with a PCL250 HMRC profile and receives a P2
  Successfully migrates a PCL250 HMRC profile during 6MFC
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
    And the subject already has the following expired credentials
      | CRI   | scenario        |
      | fraud | kenneth-score-2 |

    # New 6MFC journey with inherited identity
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'kenneth-vot-pcl250-passport'
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-only' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-changed' details with attributes to the CRI stub
            | Attribute | Values               |
            | context   | "international_user" |
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'page-ipv-success' page response with context 'updateIdentity'
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario Outline: Successfully completes an alternate doc (separate session mitigation) journey with PCL250 HMRC profile and receives P2 identity
    Given I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I call the CRI stub and get an 'access_denied' OAuth error
    Then I get a 'page-multiple-doc-check' page response
    When I submit a '<initial-cri>' event
    Then I get a '<initial-cri>' CRI response
    When I submit '<initial-invalid-doc>' details to the CRI stub
    Then I get a '<no-match-page>' page response

    # New journey with inherited identity
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'kenneth-vot-pcl250-passport'
    Then I get a '<return-no-match-page>' page response
    When I submit a 'next' event
    Then I get a '<mitigating-doc-page>' page response
    When I submit a 'next' event
    Then I get a '<mitigating-cri>' CRI response
    When I submit '<mitigating-doc>' details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
    | initial-cri     | initial-invalid-doc                        | no-match-page                            | return-no-match-page         | mitigating-doc-page               | mitigating-cri | mitigating-doc               |
    | ukPassport      | kenneth-passport-needs-alternate-doc       | pyi-passport-no-match-another-way        | pyi-passport-no-match        | pyi-continue-with-driving-licence | drivingLicence | kenneth-driving-permit-valid |
    | drivingLicence  | kenneth-driving-permit-needs-alternate-doc | pyi-driving-licence-no-match-another-way | pyi-driving-licence-no-match | pyi-continue-with-passport        | ukPassport     | kenneth-passport-valid       |
