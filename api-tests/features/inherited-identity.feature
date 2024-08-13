Feature: Inherited Identity

  Scenario: Migrate PCL 200 HMRC profile successfully with no evidence
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl200-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL200' identity
    When I start a new 'medium-confidence-pcl200-pcl250' journey
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'PCL200' identity

  Scenario: Migrate PCL 250 HMRC profile successfully with no evidence
    Given I start a new 'medium-confidence-pcl250' journey with inherited identity 'alice-vot-pcl250-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity
    When I start a new 'medium-confidence-pcl250' journey
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity

  Scenario: Migrate PCL 250 HMRC profile successfully with passport evidence
    Given I start a new 'medium-confidence-pcl250' journey with inherited identity 'kenneth-vot-pcl250-passport'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity
    When I start a new 'medium-confidence-pcl250' journey
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity

  Scenario: Migrate PCL 250 HMRC profile successfully with driving permit evidence
    Given I start a new 'medium-confidence-pcl250' journey with inherited identity 'kenneth-vot-pcl250-driving-permit'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity
    When I start a new 'medium-confidence-pcl250' journey
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity

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
