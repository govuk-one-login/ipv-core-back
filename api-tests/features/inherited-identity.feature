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
