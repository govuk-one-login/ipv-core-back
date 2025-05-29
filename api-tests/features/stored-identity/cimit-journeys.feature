Feature: D02 journeys
  Rule: P1 CIMIT - Alternate doc
    Background:
      Given I activate the 'storedIdentityService' feature set
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

  Rule: P2 CIMIT - Alternate doc
    Background:
      Given I activate the 'storedIdentityService' feature set
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
