@Build
Feature: F2F Volume Control

  Background: Start P2 journey via app but DCMAW returns OAuth error
    Given I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-multiple-doc-check' page response

  Scenario Outline: Allows use of <alternative-doc-cri> when <initial-cri> CRI returns OAuth error
    When I submit a '<initial-cri>' event
    Then I get a '<initial-cri>' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'prove-identity-another-type-photo-id' page response
    When I submit a 'otherPhotoId' event
    Then I get a '<alternative-doc-cri>' CRI response
    When I submit '<alternative-doc>' details to the CRI stub
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
    | initial-cri    | alternative-doc-cri | alternative-doc              |
    | ukPassport     | drivingLicence      | kenneth-driving-permit-valid |
    | drivingLicence | ukPassport          | kenneth-passport-valid       |

  Scenario Outline: Mitigation of alternate-doc CI via <mitigating-cri> when <mitigating-cri> initially returns OAuth error
    When I submit a '<initial-cri>' event
    Then I get a '<initial-cri>' CRI response
    When I submit '<initial-invalid-doc>' details to the CRI stub
    Then I get a '<no-match-page>' page response
    When I submit a 'next' event
    Then I get a '<mitigating-cri>' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'prove-identity-no-other-photo-id' page response
    When I submit a 'back' event
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
      | initial-cri    | initial-invalid-doc                        | no-match-page                            | mitigating-cri | mitigating-doc               |
      | ukPassport     | kenneth-passport-needs-alternate-doc       | pyi-passport-no-match-another-way        | drivingLicence | kenneth-driving-permit-valid |
      | drivingLicence | kenneth-driving-permit-needs-alternate-doc | pyi-driving-licence-no-match-another-way | ukPassport     | kenneth-passport-valid       |

  Scenario: User is able to continue to service from the prove-identity-another-type-photo-id page without identity
    When I submit a 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'prove-identity-another-type-photo-id' page response
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity

  Scenario: User can use F2F to receive identity from the prove-identity-another-type-photo-id page
    When I submit a 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'prove-identity-another-type-photo-id' page response
    When I submit an 'f2f' event
    Then I get a 'pyi-post-office' page response
    When I submit a 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'f2f' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the async CRI stub
    Then I get a 'page-face-to-face-handoff' page response

    # Return journey
    When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

  Scenario: Returns P0 when user continues to service from prove-identity-no-other-photo-id page during CI mitigation
    When I submit a 'ukPassport' event
    Then I get a 'ukPassport' CRI response
    When I submit 'kenneth-passport-needs-alternate-doc' details to the CRI stub
    Then I get a 'pyi-passport-no-match-another-way' page response
    When I submit a 'next' event
    Then I get a 'drivingLicence' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'prove-identity-no-other-photo-id' page response
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P0' identity
