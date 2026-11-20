@Build @QualityGateIntegrationTest @QualityGateRegressionTest
Feature: Token exchange
    Scenario: Same auth code used concurrently only succeeds once
      Given the subject already has the following credentials
        | CRI     | scenario               |
        | dcmaw   | kenneth-passport-valid |
        | address | kenneth-current        |
        | fraud   | kenneth-score-2        |
      When I start a new 'high-medium-confidence' journey
      Then I get a 'page-ipv-reuse' page response
      When I submit a 'next' event
      Then I get an OAuth response
      When I exchange the auth code concurrently 5 times
      Then exactly one token request succeeds
