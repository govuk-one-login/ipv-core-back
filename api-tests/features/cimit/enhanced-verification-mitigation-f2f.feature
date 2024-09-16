@Build
Feature: Mitigating CIs with enhanced verification using the F2F CRI
  Background:
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

  Rule: Same session journeys

    Scenario Outline: Same session F2F enhanced verification mitigation - successful
      When I submit an 'f2f' event
      Then I get an 'f2f' CRI response
      When I submit '<document-details>' details to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response
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
      When I get a 'temporarily_unavailable' OAuth error from the CRI stub
      Then I get a 'pyi-technical' page response

    Scenario: Same session F2F enhanced verification mitigation - user abandons DCMAW then mitigates with F2F
      When I submit a 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I get an 'access_denied' OAuth error from the CRI stub
      Then I get a 'pyi-post-office' page response
      When I submit a 'next' event
      Then I get an 'f2f' CRI response
      When I submit 'kenneth-passport-valid' details to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response
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
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get an 'f2f' CRI response
      When I submit '<document-details>' details to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response
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
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get an 'f2f' CRI response
      When I get a 'temporarily_unavailable' OAuth error from the CRI stub
      Then I get a 'pyi-technical' page response

    Scenario: Separate session F2F enhanced verification mitigation - user abandons DCMAW and mitigates with F2F
      Given I start a new 'medium-confidence' journey
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
      Then I get an 'f2f' CRI response
      When I submit 'kenneth-passport-valid' details to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start a new 'medium-confidence' journey and return to a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity
