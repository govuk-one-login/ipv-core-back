@Build
Feature:  Mitigating CIs with enhanced verification using the DCMAW CRI

  Background:
    # Navigate to KBV CRI and apply NEEDS-ENHANCED-VERIFICATION CI
    Given I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I get an 'access_denied' OAuth error from the CRI stub
    Then I get a 'page-multiple-doc-check' page response
    When I submit a 'drivingLicence' event
    Then I get a 'drivingLicence' CRI response
    When I submit 'kenneth-driving-permit-valid' details to the CRI stub
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-pre-experian-kbv-transition' page response
    When I submit a 'next' event
    Then I get a 'kbv' CRI response
    When I submit 'kenneth-needs-enhanced-verification' details with attributes to the CRI stub
      | Attribute          | Values                                          |
      | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":2} |
    Then I get a 'pyi-suggest-other-options' page response

  Rule: Same session journeys

    Scenario Outline: Same session DCMAW enhanced verification mitigation - successful
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit '<document-details>' details to the CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P2' identity

      Examples:
        | document-details             |
        | kenneth-passport-valid       |
        | kenneth-driving-permit-valid |

    Scenario: Same session DCMAW enhanced verification mitigation - user abandons DCMAW then escapes
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I get a 'access_denied' OAuth error from the CRI stub
      Then I get a 'pyi-post-office' page response
      When I submit an 'end' event
      Then I get a 'pyi-another-way' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

    Scenario: Same session DCMAW enhanced verification mitigation - breaching CI received from DCMAW
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-with-breaching-ci' details to the CRI stub
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

    Scenario: Same session DCMAW enhanced verification mitigation - DCMAW is unavailable
      Given I activate the 'dcmawOffTest' feature set
      When I submit an 'appTriage' event
      Then I get a 'pyi-technical' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

  Rule: Separate session journeys

    Scenario Outline: Separate session DCMAW enhanced verification mitigation - successful
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit '<document-details>' details to the CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
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

      Examples:
        | document-details             |
        | kenneth-passport-valid       |
        | kenneth-driving-permit-valid |

    Scenario: Separate session DCMAW enhanced verification mitigation - breaching CI received from DCMAW
      When I start a new 'medium-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-passport-with-breaching-ci' details to the CRI stub
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

    Scenario: Separate session DCMAW enhanced verification mitigation - DCMAW is unavailable
      When I start a new 'medium-confidence' journey with feature set 'dcmawOffTest'
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      # This is just ensuring that we handle this journey. It's not really an expected case.
      Then I get a 'pyi-technical' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
