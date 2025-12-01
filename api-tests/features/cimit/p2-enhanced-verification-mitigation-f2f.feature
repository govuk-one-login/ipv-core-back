@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Mitigating CIs with enhanced verification using the F2F CRI
  Background:
    Given I activate the 'disableStrategicApp' feature set
    When I start a new 'medium-confidence' journey
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
    Then I get a 'experianKbv' CRI response
    When I submit 'kenneth-needs-enhanced-verification' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'photo-id-security-questions-find-another-way' page response

  Rule: Same session journeys

    Scenario Outline: Same session F2F enhanced verification mitigation - successful
      When I submit an 'f2f' event
      Then I get an 'f2f' CRI response
      When I submit '<document-details>' details with attributes to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":0} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | document-details             |
        | kenneth-passport-valid       |
        | kenneth-driving-permit-valid |

    Scenario: Same session F2F enhanced verification mitigation - OAuth error from F2F CRI
      When I submit an 'f2f' event
      Then I get an 'f2f' CRI response
      When I call the CRI stub with attributes and get a 'temporarily_unavailable' OAuth error
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":0} |
      Then I get a 'pyi-technical' page response

    Scenario: Same session F2F enhanced verification mitigation - async queue error - dropout
      When I submit an 'f2f' event
      Then I get an 'f2f' CRI response
      When I get an error from the async CRI stub
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new 'medium-confidence' journeys until I get a 'pyi-f2f-technical' page response
      When I submit a 'end' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity without a TICF VC

    Scenario: Same session F2F enhanced verification mitigation - async queue error - continue from pyi-f2f-technical page
      When I submit an 'f2f' event
      Then I get an 'f2f' CRI response
      When I get an error from the async CRI stub
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new 'medium-confidence' journeys until I get a 'pyi-f2f-technical' page response
      When I submit a 'next' event
      Then I get a 'page-ipv-identity-document-start' page response

    Scenario: Same session F2F enhanced verification mitigation - user abandons DCMAW then mitigates with F2F
      When I submit a 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'pyi-post-office' page response
      When I submit a 'next' event
      Then I get an 'f2f' CRI response
      When I submit 'kenneth-passport-valid' details with attributes to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":0} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

  Rule: Separate session journeys

    Scenario Outline: Separate session F2F enhanced verification mitigation - successful
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
      When I submit '<document-details>' details with attributes to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | document-details             |
        | kenneth-passport-valid       |
        | kenneth-driving-permit-valid |

    Scenario: Separate session F2F enhanced verification mitigation - OAuth error from F2F CRI
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
      When I call the CRI stub with attributes and get a 'temporarily_unavailable' OAuth error
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'pyi-technical' page response

    Scenario: Separate session F2F enhanced verification mitigation - async queue error
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
      Then I get a 'P0' identity without a TICF VC

    Scenario: Separate session F2F enhanced verification mitigation - user abandons DCMAW and mitigates with F2F
      Given I start a new 'medium-confidence' journey
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
      Then I get an 'f2f' CRI response
      When I submit 'kenneth-passport-valid' details with attributes to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

    Scenario: Separate session F2F enhanced verification mitigation - user fails DCMAW (e.g. failed likeness) - mitigate via F2F
      Given I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-fail-no-ci' details to the CRI stub
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
      When I submit 'kenneth-passport-valid' details with attributes to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":3} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new 'medium-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
