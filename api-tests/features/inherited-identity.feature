@Build
Feature: Inherited Identity

  Scenario Outline: Inherited Identity Scenarios
    Given I start a new '<journey-type>' journey with inherited identity '<inherited-identity>'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a '<expected-identity>' identity
    When I start a new '<journey-type>' journey
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a '<expected-identity>' identity

    Examples:
      | journey-type                    | inherited-identity                | expected-identity |
      | medium-confidence-pcl200-pcl250 | alice-vot-pcl200-no-evidence      | PCL200            |
      | medium-confidence-pcl200-pcl250 | alice-vot-pcl250-no-evidence      | PCL250            |
      | medium-confidence-pcl250        | kenneth-vot-pcl250-passport       | PCL250            |
      | medium-confidence-pcl250        | kenneth-vot-pcl250-driving-permit | PCL250            |

  Scenario: Migrate PCL 200 HMRC profile successfully with no evidence and returns with P2
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl200-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL200' identity
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response

  Scenario: Migrate PCL 200 HMRC profile successfully with no evidence and returns with P2/PCL250
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl200-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL200' identity
    When I start a new 'medium-confidence-pcl250' journey
    Then I get a 'page-ipv-identity-document-start' page response

  Scenario: Migrate PCL 250 HRMC profile successfully with no evidence and returns with P2
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl250-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response

  Scenario: Migrate PCL 250 HRMC profile successfully with no evidence and returns with P2/PCL250
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl250-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity
    When I start a new 'medium-confidence-pcl250' journey
    Then I get an OAuth response

  Scenario Outline: P2 identity takes priority over successfully migrated PCL200 <evidence-state>
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
    When I submit 'kenneth-score-2' details to the CRI stub
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    # New journey with inherited identity
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity '<inherited-identity>'
    Then I get a 'page-ipv-reuse' page response
    When I submit an 'next' event
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity

    Examples:
    | inherited-identity                | evidence-state   |
    | alice-vot-pcl200-no-evidence      | with no evidence |
    | kenneth-vot-pcl250-driving-permit | with evidence    |

  Scenario: Previous PCL 200 is replaced by new PCL 200 for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'kenneth-vot-pcl200-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL200' identity
    And my identity 'GivenName' is 'Kenneth'

    # New journey with new PCL200 inherited identity for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl200-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL200' identity
    And my identity 'GivenName' is 'Alice'

  Scenario: Previous PCL 200 is replaced by new PCL 250 for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'kenneth-vot-pcl200-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL200' identity
    And my identity 'GivenName' is 'Kenneth'

    # New journey with new PCL200 inherited identity for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl250-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity
    And my identity 'GivenName' is 'Alice'

  Scenario: Previous PCL 200 is replaced by new PCL 250 with DL evidence for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl200-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL200' identity
    And my identity 'GivenName' is 'Alice'

    # New journey with new PCL200 inherited identity for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'kenneth-vot-pcl250-driving-permit'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity
    And my identity 'GivenName' is 'Kenneth'

  Scenario: Previous PCL 200 is replaced by new PCL 250 with passport evidence for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl200-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL200' identity
    And my identity 'GivenName' is 'Alice'

    # New journey with new PCL200 inherited identity for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'kenneth-vot-pcl250-passport'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity
    And my identity 'GivenName' is 'Kenneth'

  Scenario: Previous PCL 250 is not replaced by new PCL 200 for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl250-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity
    And my identity 'GivenName' is 'Alice'

    # New journey with new PCL200 inherited identity for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'kenneth-vot-pcl200-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity
    And my identity 'GivenName' is 'Alice'
