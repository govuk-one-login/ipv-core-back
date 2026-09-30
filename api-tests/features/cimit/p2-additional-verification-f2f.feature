@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature:  Mitigating CIs with additional verification using the F2F CRI
  Background: Start P2 no photo id journey
    Given I activate the 'openBanking' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'prove-identity-online' page response
    When I submit an 'next' event
    Then I get a 'prove-identity-online-banking' page response
    When I submit an 'next' event
    Then I get a 'claimedIdentity' CRI response
    When I submit 'kenneth-current' details with attributes to the CRI stub
      | Attribute | Values         |
      | context   | "bank_account" |
    Then I get a 'nino' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":2} |
    Then I get an 'openBanking' CRI response
    When I submit 'kenneth-needs-additional-verification' details to the CRI stub
    Then I get a 'no-photo-id-web-find-another-way' page response and pageContext
      | Context | Value       |
      | reason  | openBanking |

  Scenario: Same session F2F additional verification mitigation - OAuth error from F2F CRI
    When I submit an 'f2f' event
    Then I get a 'pyi-post-office' page response
    When I submit a 'next' event
    Then I get an 'f2f' CRI response
    When I call the CRI stub with attributes and get a 'temporarily_unavailable' OAuth error
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
    Then I get a 'pyi-technical' page response

  Scenario: Same session F2F additional verification mitigation - async queue error - dropout
    When I submit an 'f2f' event
    Then I get a 'pyi-post-office' page response
    When I submit a 'next' event
    Then I get an 'f2f' CRI response
    When I get an error from the async CRI stub
    Then I get a 'page-face-to-face-handoff' page response

      # Return journey
    When I start new 'medium-confidence' journeys until I get a 'pyi-f2f-technical' page response
    When I submit a 'end' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I am issued a 'P0' identity without a TICF VC
    And I don't have a stored identity in EVCS

  Scenario Outline: Separate session F2F additional verification mitigation - successful
    When I start a new 'medium-confidence' journey
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
    Then I get an 'f2f' CRI response
    When I submit '<document-details>' details with attributes to the async CRI stub that mitigate the 'NEEDS-ADDITIONAL-VERIFICATION' CI
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
    Then I get a 'page-face-to-face-handoff' page response

      # Return journey
    When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I am issued a 'P2' identity
    And I have a stored identity record with a 'P2' max vot

    Examples:
      | document-details             |
      | kenneth-passport-valid       |
      | kenneth-driving-permit-valid |

  Scenario: Separate session F2F additional verification mitigation - async queue error
    When I start a new 'medium-confidence' journey
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
    Then I get an 'f2f' CRI response
    When I get an error from the async CRI stub
    Then I get a 'page-face-to-face-handoff' page response

      # Return journey
    When I start new 'medium-confidence' journeys until I get a 'pyi-f2f-technical' page response
    When I submit a 'end' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I am issued a 'P0' identity without a TICF VC
    And I don't have a stored identity in EVCS

  Scenario: Separate session F2F additional verification mitigation - user abandons DCMAW and mitigates with F2F
    Given I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response and pageContext
      | Context    | Value |
      | deviceType | dad   |
    When I submit a 'neither' event
    Then I get a 'pyi-triage-buffer' page response
    When I submit an 'anotherWay' event
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
    Then I get an 'f2f' CRI response
    When I submit 'kenneth-passport-valid' details with attributes to the async CRI stub that mitigate the 'NEEDS-ADDITIONAL-VERIFICATION' CI
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
    Then I get a 'page-face-to-face-handoff' page response

      # Return journey
    When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I am issued a 'P2' identity
    And I have a stored identity record with a 'P2' max vot

  Scenario: Separate session F2F additional verification mitigation - user fails DCMAW (e.g. failed likeness) - mitigate via F2F
    Given I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get an 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response and pageContext
      | Context    | Value |
      | deviceType | mam   |
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response and pageContext
      | Context    | Value  |
      | smartphone | iphone |
      | isAppOnly  | false  |
    When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get a 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    When I submit the returned journey event
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
    Then I get an 'f2f' CRI response
    When I submit 'kenneth-passport-valid' details with attributes to the async CRI stub that mitigate the 'NEEDS-ADDITIONAL-VERIFICATION' CI
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
    Then I get a 'page-face-to-face-handoff' page response

      # Return journey
    When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I am issued a 'P2' identity
    And I have a stored identity record with a 'P2' max vot

  Scenario Outline: Successful Open Banking mitigation - user mitigates CI with f2f using <doc>
    When I submit an 'f2f' event
    Then I get a 'pyi-post-office' page response
    When I submit a 'next' event
    Then I get an 'f2f' CRI response
    When I submit '<valid-document>' details with attributes to the async CRI stub that mitigate the 'NEEDS-ADDITIONAL-VERIFICATION' CI
      | Attribute          | Values                                      |
      | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
    Then I get a 'page-face-to-face-handoff' page response

      # Return journey
    When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I am issued a 'P2' identity
    And I have a stored identity record with a 'P2' max vot

    Examples:
      | doc             | valid-document               |
      | passport        | kenneth-driving-permit-valid |
      | driving licence | kenneth-passport-valid       |
