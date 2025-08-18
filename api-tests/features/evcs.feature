@RealEvcs # Temporary test to be run in whitelisted VPC
Feature: P2 Reuse journey - Real EVCS

  Scenario: Reuse journey - user has to paginate VCs
    Given I activate the 'disableStrategicApp' feature set
    When I start a new 'high-medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'dcmaw' CRI response
    When I submit 'kenneth-passport-valid' details to the CRI stub
    Then I get a 'page-dcmaw-success' page response
    When I submit a 'next' event
    Then I get an 'address' CRI response
    When I submit 'kenneth-current' details to the CRI stub
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response

    #
    When I start a new 'medium-confidence' journey
    Then I get a 'confirm-your-details' page response
    When I submit a 'next' event
    Then I get a 'fraud' CRI response
    When I submit 'kenneth-unavailable' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response with context 'repeatFraudCheck'
    When I submit a 'next' event
    Then I get an OAuth response