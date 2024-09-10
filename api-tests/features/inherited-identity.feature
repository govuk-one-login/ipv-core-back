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

  Scenario Outline: Migrate <expected-identity> HMRC profile successfully with no evidence and returns with <vtr> - requires identity to be proved for stronger profile
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity '<inherited-identity>'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a '<expected-identity>' identity
    When I start a new '<return-journey-type>' journey
    Then I get a 'page-ipv-identity-document-start' page response

    Examples:
    | inherited-identity            | expected-identity | return-journey-type      | vtr       |
    |  alice-vot-pcl200-no-evidence | PCL200            | medium-confidence        | P2        |
    |  alice-vot-pcl200-no-evidence | PCL200            | medium-confidence-pcl250 | P2/PCL250 |
    | alice-vot-pcl250-no-evidence  | PCL250            | medium-confidence        | P2        |

  Scenario: Migrate PCL250 HRMC profile successfully with no evidence and returns with P2/PCL250
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

  Scenario Outline: Previous <old-identity> is <is-replaced> with new <new-identity> for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity '<old-details>'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a '<old-expected-vot>' identity
    And my identity 'GivenName' is '<old-expected-name>'

    # New journey with new inherited identity for the same user
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity '<new-details>'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a '<new-expected-vot>' identity
    And my identity 'GivenName' is '<new-expected-name>'

    Examples:
    | old-identity | old-details                    | old-expected-name | old-expected-vot | new-identity | new-details                          | new-expected-name | new-expected-vot | is-replaced  |
    | PCL200       | kenneth-vot-pcl200-no-evidence | Kenneth           | PCL200           | PCL200       | alice-vot-pcl200-no-evidence         | Alice             | PCL200           | replaced     |
    | PCL200       | kenneth-vot-pcl200-no-evidence | Kenneth           | PCL200           | PCL250       | alice-vot-pcl250-no-evidence         | Alice             | PCL250           | replaced     |
    | PCL200       | alice-vot-pcl200-no-evidence   | Alice             | PCL200           | PCL250       | kenneth-vot-pcl250-driving-permit    | Kenneth           | PCL250           | replaced     |
    | PCL200       | alice-vot-pcl200-no-evidence   | Alice             | PCL200           | PCL250       | kenneth-vot-pcl250-passport          | Kenneth           | PCL250           | replaced     |
    | PCL250       | alice-vot-pcl250-no-evidence   | Alice             | PCL250           | PCL200       | kenneth-vot-pcl200-no-evidence       | Alice             | PCL250           | not replaced |
