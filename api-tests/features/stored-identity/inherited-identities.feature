@Build
Feature: Inherited Identity journeys
  Background: Enable stored identity service feature flag
    Given I activate the 'storedIdentityService,disableStrategicApp' feature set

  Scenario Outline: Inherited Identity Reuse
    Given I start a new '<journey-type>' journey with inherited identity '<inherited-identity>'
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a '<expected-identity>' identity
    And I have a 'HMRC' stored identity record type with a '<expected-identity>' vot

    # Inherited identity reuse
    When I start a new '<journey-type>' journey
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a '<expected-identity>' identity
    And I have a 'HMRC' stored identity record type with a '<expected-identity>' vot

    Examples:
      | journey-type                    | inherited-identity                | expected-identity |
      | medium-confidence-pcl200-pcl250 | alice-vot-pcl200-no-evidence      | PCL200            |
      | medium-confidence-pcl200-pcl250 | alice-vot-pcl250-no-evidence      | PCL250            |

  Scenario: Stronger inherited identity overrides initial weaker inherited identity
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl200-no-evidence'
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'PCL200' identity
    And I have a 'HMRC' stored identity record type with a 'PCL200' vot

    # New journey with stronger inherited identity
    When I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl250-no-evidence'
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity
    And I have a 'HMRC' stored identity record type with a 'PCL250' vot

  Scenario: Stronger inherited identity is kept if new inherited identity is weaker
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl250-no-evidence'
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity
    And I have a 'HMRC' stored identity record type with a 'PCL250' vot

    # New journey with weaker inherited identity
    When I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl200-no-evidence'
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'PCL250' identity
    And I have a 'HMRC' stored identity record type with a 'PCL250' vot

  Scenario: P2 identity takes priority over successfully migrated inherited identity
    Given I start a new 'medium-confidence' journey
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
    When I submit 'kenneth-score-2' details with attributes to the CRI stub
      | Attribute          | Values                   |
      | evidence_requested | {"identityFraudScore":1} |
    Then I get a 'page-ipv-success' page response
    When I submit a 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And I have a 'GPG45' stored identity record type with a 'P3' vot

    # New journey with inherited identity
    Given I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl250-no-evidence'
    Then I get a 'page-ipv-reuse' page response
    When I submit an 'next' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'P2' identity
    And I have a 'GPG45' stored identity record type with a 'P3' vot
