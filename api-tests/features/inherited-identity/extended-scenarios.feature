Feature: Inherited identity extended scenarios
  Scenario Outline: Successfully migrates <inherited-identity> HRMC profile after partial P2 journey
    Given I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response

    # New journey with inherited identity
    When I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity '<identity-details>'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a '<expected-identity>' identity

    Examples:
    | inherited-identity | identity-details             | expected-identity |
    | PCL200             | alice-vot-pcl200-no-evidence | PCL200            |
    | PCL250             | kenneth-vot-pcl250-passport  | PCL250            |

  Scenario Outline: Successful enhanced verification mitigation with a <inherited-identity> HMRC profile and receives a P2
    Given I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-multiple-doc-check' page response
    When I submit a 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-needs-enhanced-verification' details to the CRI stub
    Then I get a 'pyi-suggest-other-options' page response

    # New journey with inherited identity - user still needs to mitigate the CI
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity '<identity-details>'
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'pyi-post-office' page response
    When I submit a 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
    | inherited-identity | identity-details             |
    | PCL200             | alice-vot-pcl200-no-evidence |
    | PCL250             | kenneth-vot-pcl250-passport  |

  Scenario Outline: Fails to migrate <inherited-identity> HMRC profile when user has failed F2F with CI
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
    When I submit 'kenneth-passport-breaching' details to the async CRI stub
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    When I start a new 'medium-confidence' journey and return to a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

    # New journey with inherited identity for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity '<identity-details>'
    Then I get a 'pyi-no-match' page response
    When I submit a 'next' event
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

    Examples:
      | inherited-identity | identity-details             |
      | PCL200             | alice-vot-pcl200-no-evidence |
      | PCL250             | kenneth-vot-pcl250-passport  |

  Scenario Outline: Successfully migrates <inherited-identity> HMRC profile for user with pending F2F
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
    When I submit 'kenneth-passport-breaching' details to the CRI stub
    Then I get a 'page-face-to-face-handoff' page response
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-pending' page response

    # Return journey with inherited identity for the same user
    When I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity '<identity-details>'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a '<expected-identity>' identity

    Examples:
    | inherited-identity | identity-details             | expected-identity |
    | PCL200             | alice-vot-pcl200-no-evidence | PCL200            |
    | PCL250             | kenneth-vot-pcl250-passport  | PCL250            |

  Scenario Outline: Successfully migrates <inherited-identity> HMRC profile when user has failed F2F (no CI)
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
    When I get an error from the async CRI stub
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    When I start a new 'medium-confidence' journey and return to a 'pyi-f2f-technical' page response
    When I submit a 'end' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity without a TICF VC

    # New journey with inherited identity for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity '<identity-details>'
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a '<expected-identity>' identity

    Examples:
      | inherited-identity | identity-details             | expected-identity |
      | PCL200             | alice-vot-pcl200-no-evidence | PCL200            |
      | PCL250             | kenneth-vot-pcl250-passport  | PCL250            |

  Scenario Outline: Successfully completes reprove identity journey with a <inherited-identity> HMRC profile and receives a P2
    Given I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response

    # Start reprove identity journey with inherited identity after incomplete P2
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with reprove identity and with inherited identity '<identity-details>'
    Then I get a 'reprove-identity-start' page response
    When I submit a 'next' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-multiple-doc-check' page response
    When I submit a 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | inherited-identity | identity-details             |
      | PCL200             | alice-vot-pcl200-no-evidence |
      | PCL250             | kenneth-vot-pcl250-passport  |

  Scenario Outline: Successfully completes a 6MFC journey with a <inherited-identity> HMRC profile and receives a P2
  Successfully migrates a <inherited-identity> HMRC profile during 6MFC
    Given the subject already has the following credentials
      | CRI     | scenario                     |
      | dcmaw   | kenneth-driving-permit-valid |
      | address | kenneth-current              |
    And the subject already has the following expired credentials
      | CRI   | scenario        |
      | fraud | kenneth-score-2 |

    # New 6MFC journey with inherited identity
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity '<identity-details>'
    Then I get a 'confirm-your-details' page response
    When I submit a 'address-only' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
      | inherited-identity | identity-details             |
      | PCL200             | alice-vot-pcl200-no-evidence |
      | PCL250             | kenneth-vot-pcl250-passport  |

  Scenario Outline: Successfully completes separate sessions alternate doc journey with <inherited-identity> HMRC profile and receives P2 identity
    Given I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-multiple-doc-check' page response
    When I submit a '<initial-cri>' event
    Then I get a '<initial-cri>' CRI response
    When I submit '<initial-invalid-doc>' details to the CRI stub
    Then I get a '<no-match-page>' page response

    # New journey with inherited identity
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity '<identity-details>'
    Then I get a '<return-no-match-page>' page response
    When I submit a 'next' event
    Then I get a '<mitigating-doc-page>' page response
    When I submit a 'next' event
    Then I get a '<mitigating-cri>' CRI response
    When I submit '<mitigating-doc>' details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
    | inherited-identity | identity-details             | initial-cri     | initial-invalid-doc                        | no-match-page                            | return-no-match-page         | mitigating-doc-page               | mitigating-cri | mitigating-doc               |
    | PCL200             | alice-vot-pcl200-no-evidence | ukPassport      | kenneth-passport-needs-alternate-doc       | pyi-passport-no-match-another-way        | pyi-passport-no-match        | pyi-continue-with-driving-licence | drivingLicence | kenneth-driving-permit-valid |
    | PCL250             | kenneth-vot-pcl250-passport  | ukPassport      | kenneth-passport-needs-alternate-doc       | pyi-passport-no-match-another-way        | pyi-passport-no-match        | pyi-continue-with-driving-licence | drivingLicence | kenneth-driving-permit-valid |
    | PCL200             | alice-vot-pcl200-no-evidence | drivingLicence  | kenneth-driving-permit-needs-alternate-doc | pyi-driving-licence-no-match-another-way | pyi-driving-licence-no-match | pyi-continue-with-passport        | ukPassport     | kenneth-passport-valid       |
    | PCL250             | kenneth-vot-pcl250-passport  | drivingLicence  | kenneth-driving-permit-needs-alternate-doc | pyi-driving-licence-no-match-another-way | pyi-driving-licence-no-match | pyi-continue-with-passport        | ukPassport     | kenneth-passport-valid       |
