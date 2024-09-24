Feature: Unhappy paths
  Scenario: Unrecoverable error from orch
    When I start a new 'medium-confidence' journey with invalid redirect url 'https://orch.stubs.account.gov.uk/invalid-callback'
    Then I get an 'InitialiseIpvSessionError' error with 'Failed to parse the session start request' message and with status code '400'

  Scenario: Invalid inherited identity JWT
    When I start a new 'medium-confidence-pcl200-pcl250' inherited identity journey with an invalid inherited identity jwt
    Then I get a 'pyi-technical' page response
