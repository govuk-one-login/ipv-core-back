Feature: Inherited identity extended scenarios
  Scenario: Successfully migrates PCL200 HRMC profile after partial P2 journey
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

    # New journey with inherited identity
    When I start a new 'medium-confidence-pcl200-pcl250' journey with inherited identity 'alice-vot-pcl200-no-evidence'
    Then I get an OAuth response
    And an 'IPV_INHERITED_IDENTITY_VC_RECEIVED' audit event was recorded [local only]
    When I use the OAuth response to get my identity
    Then I get a 'PCL200' identity

    # New journey
    When I start a new 'medium-confidence-pcl200-pcl250' journey
    Then I get an OAuth response
    When I use the OAuth response to get my identity
    Then I get a 'PCL200' identity
