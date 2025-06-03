Feature: Stored Identity Service - CIMIT journeys
  Background:
    Given I activate the 'storedIdentityService' feature set

  Rule: P1 - D02 Mitigation
    Background:
      Given I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'page-multiple-doc-check' page response with context 'nino'

    Scenario Outline: Alternate doc mitigation via passport or DL
      When I submit an '<initialCri>' event
      Then I get a '<initialCri>' CRI response
      When I submit '<initialInvalidDoc>' details to the CRI stub
      Then I get a '<noMatchPage>' page response
      When I submit a 'next' event
      Then I get a '<mitigatingCri>' CRI response
      When I submit '<mitigatingDoc>' details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'kbv' CRI response
      When I submit 'kenneth-score-1' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event

      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And I have a 'GPG45' stored identity record type with a 'P1' vot

      Examples:
        | initialCri     | initialInvalidDoc                          | noMatchPage                              | mitigatingCri  | mitigatingDoc                |
        | drivingLicence | kenneth-driving-permit-needs-alternate-doc | pyi-driving-licence-no-match-another-way | ukPassport     | kenneth-passport-valid       |
        | ukPassport     | kenneth-passport-needs-alternate-doc       | pyi-passport-no-match-another-way        | drivingLicence | kenneth-driving-permit-valid |

    Scenario Outline: Alternate doc mitigation via passport or DL - separate session
      When I submit an '<initialCri>' event
      Then I get a '<initialCri>' CRI response
      When I submit '<initialInvalidDoc>' details to the CRI stub
      Then I get a '<noMatchPage>' page response
      When I submit a 'next' event
      Then I get a '<mitigatingCri>' CRI response

      # User drops out of previous CRI without mitigating and starts a new journey
      Given I start a new 'low-confidence' journey
      Then I get a '<separateSessionNoMatch>' page response
      When I submit a 'next' event
      Then I get a '<mitigationStart>' page response
      When I submit a 'next' event
      Then I get a '<mitigatingCri>' CRI response
      When I submit '<mitigatingDoc>' details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'page-pre-experian-kbv-transition' page response
      When I submit a 'next' event
      Then I get a 'kbv' CRI response
      When I submit 'kenneth-score-1' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
      Then I get a 'page-ipv-success' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And I have a 'GPG45' stored identity record type with a 'P1' vot

      Examples:
        | initialCri     | initialInvalidDoc                          | noMatchPage                              | separateSessionNoMatch       | mitigationStart                   | mitigatingCri  | mitigatingDoc                |
        | drivingLicence | kenneth-driving-permit-needs-alternate-doc | pyi-driving-licence-no-match-another-way | pyi-driving-licence-no-match | pyi-continue-with-passport        | ukPassport     | kenneth-passport-valid       |
        | ukPassport     | kenneth-passport-needs-alternate-doc       | pyi-passport-no-match-another-way        | pyi-passport-no-match        | pyi-continue-with-driving-licence | drivingLicence | kenneth-driving-permit-valid |

  Rule: P2 - D02 Mitigation
    Background:
      Given I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'page-multiple-doc-check' page response

    Scenario Outline: Alternate doc mitigation via passport or DL
      When I submit an '<initialCri>' event
      Then I get a '<initialCri>' CRI response
      When I submit '<initialInvalidDoc>' details to the CRI stub
      Then I get a '<noMatchPage>' page response
      When I submit a 'next' event
      Then I get a '<mitigatingCri>' CRI response
      When I submit '<mitigatingDoc>' details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details to the CRI stub
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
      And I have a 'GPG45' stored identity record type with a 'P2' vot

      Examples:
        | initialCri     | initialInvalidDoc                          | noMatchPage                              | mitigatingCri  | mitigatingDoc                |
        | drivingLicence | kenneth-driving-permit-needs-alternate-doc | pyi-driving-licence-no-match-another-way | ukPassport     | kenneth-passport-valid       |
        | ukPassport     | kenneth-passport-needs-alternate-doc       | pyi-passport-no-match-another-way        | drivingLicence | kenneth-driving-permit-valid |

    Scenario Outline: Alternate doc mitigation via passport or DL - separate session
      When I submit an '<initialCri>' event
      Then I get a '<initialCri>' CRI response
      When I submit '<initialInvalidDoc>' details to the CRI stub
      Then I get a '<noMatchPage>' page response
      When I submit a 'next' event
      Then I get a '<mitigatingCri>' CRI response

      # User drops out of previous CRI without mitigating and starts a new journey
      And I don't have a stored identity in EVCS
      Given I start a new 'medium-confidence' journey
      Then I get a '<separateSessionNoMatch>' page response
      When I submit a 'next' event
      Then I get a '<mitigationStart>' page response
      When I submit a 'next' event
      Then I get a '<mitigatingCri>' CRI response
      When I submit '<mitigatingDoc>' details to the CRI stub that mitigate the 'NEEDS-ALTERNATE-DOC' CI
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details to the CRI stub
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
      And I have a 'GPG45' stored identity record type with a 'P2' vot

      Examples:
        | initialCri     | initialInvalidDoc                          | noMatchPage                              | separateSessionNoMatch       | mitigationStart                   | mitigatingCri  | mitigatingDoc                |
        | drivingLicence | kenneth-driving-permit-needs-alternate-doc | pyi-driving-licence-no-match-another-way | pyi-driving-licence-no-match | pyi-continue-with-passport        | ukPassport     | kenneth-passport-valid       |
        | ukPassport     | kenneth-passport-needs-alternate-doc       | pyi-passport-no-match-another-way        | pyi-passport-no-match        | pyi-continue-with-driving-licence | drivingLicence | kenneth-driving-permit-valid |

  Rule: P1 - V03 Enhanced Verification
    Background:
      Given I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I call the CRI stub and get an 'access_denied' OAuth error
      Then I get a 'page-multiple-doc-check' page response with context 'nino'
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
      When I submit 'kenneth-needs-enhanced-verification' details with attributes to the CRI stub
        | Attribute          | Values                                          |
        | evidence_requested | {"scoringPolicy":"gpg45","verificationScore":1} |
      Then I get a 'photo-id-security-questions-find-another-way' page response

    Scenario Outline: Successful F2F enhanced verification mitigation - separate session
      When I submit an 'f2f' event
      Then I get an 'f2f' CRI response
      When I submit '<document-details>' details with attributes to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":0} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new 'low-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity
      And I have a 'GPG45' stored identity record type with a 'P2' vot

      Examples:
        | document-details             |
        | kenneth-passport-valid       |
        | kenneth-driving-permit-valid |

    Scenario Outline: Successful F2F enhanced verification mitigation - separate session
      And I don't have a stored identity in EVCS
      When I start a new 'low-confidence' journey
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
      When I submit '<document-details>' details with attributes to the async CRI stub that mitigate the 'NEEDS-ENHANCED-VERIFICATION' CI
        | Attribute          | Values                                      |
        | evidence_requested | {"scoringPolicy":"gpg45","strengthScore":2} |
      Then I get a 'page-face-to-face-handoff' page response

      # Return journey
      When I start new 'low-confidence' journeys until I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P1' identity

      Examples:
        | document-details             |
        | kenneth-passport-valid       |
        | kenneth-driving-permit-valid |
