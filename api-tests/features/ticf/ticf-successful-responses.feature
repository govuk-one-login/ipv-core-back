@Build
Feature: TICF successful responses
  Rule: TICF returns CI
    Scenario: New P2 identity journey via app - TICF returns a CI
      Given TICF CRI will respond with default parameters and
        | cis | BREACHING                   |
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
      Then I get a 'page-dcmaw-success' page response
      When I submit a 'next' event
      Then I get an 'address' CRI response
      When I submit 'kenneth-current' details to the CRI stub
      Then I get a 'fraud' CRI response
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And the TICF VC has properties
        | cis  | BREACHING                    |
        | type | RiskAssessment               |

    Scenario: New P2 identity via F2F - TICF request returns a CI
      Given TICF CRI will respond with default parameters
        | cis  | BREACHING                    |
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
      When I submit 'kenneth-score-2' details to the CRI stub
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And the TICF VC has properties
        | cis  | BREACHING                    |
        | type | RiskAssessment               |

    Scenario: TICF request returns a CI on reuse journey
      Given the subject already has the following credentials
        | CRI     | scenario                     |
        | dcmaw   | kenneth-driving-permit-valid |
        | address | kenneth-current              |
        | fraud   | kenneth-score-2              |
      And TICF CRI will respond with default parameters and
        | cis     | BREACHING                    |
      When I start a new 'medium-confidence' journey
      Then I get a 'pyi-no-match' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity
      And the TICF VC has properties
        | cis  | BREACHING                    |
        | type | RiskAssessment               |

  Rule: TICF response delay less than 2s
    Scenario: Via app - TICF request has a response delay less than 5s
      Given TICF CRI will respond with default parameters
        | responseDelay | 1         |
      And I activate the 'ticfCriBeta' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
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
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |

  Rule: TICF request times out
    Scenario: Via app - TICF request times out
      # To prime TICF to time out, we set txn to be undefined
      Given TICF CRI will respond with default parameters
        | txn   |                             |
      And I activate the 'ticfCriBeta' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'dcmaw' CRI response
      When I submit 'kenneth-driving-permit-valid' details to the CRI stub
      Then I get a 'drivingLicence' CRI response
      When I submit 'kenneth-driving-permit-valid' details with attributes to the CRI stub
        | Attribute | Values          |
        | context   | "check_details" |
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
      And the TICF VC has properties
        | cis  |                              |
        | type | RiskAssessment               |
        | txn  |                              |
