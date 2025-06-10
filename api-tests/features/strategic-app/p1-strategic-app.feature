@Build @InitialisesDCMAWSessionState
Feature: M2B Strategic App Journeys
  Rule: Photo ID
    Background: Start journey
      Given I activate the 'strategicApp' feature set
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'appTriage' event
      Then I get a 'identify-device' page response

    Scenario: Happy path MAM journey declared iphone
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
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
      Then I get a 'P1' identity

    Scenario: MAM journey cross-browser scenario happy path
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback in a separate session
      Then I get an error response with message 'Missing ipv session id header' and status code '400'
      # Wait for the VC to be received before continuing. In the usual case the VC will be received well before the user
      # has managed to log back in to the site.
      When I poll for async DCMAW credential receipt
      And I start a new 'low-confidence' journey
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
      Then I get a 'P1' identity

    Scenario: MAM journey credential fails with no ci and continues to other methods
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get an 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get an 'page-multiple-doc-check' page response with context 'nino'

    Scenario: MAM journey credential fails with ci and goes to no match page
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC with a CI
      # And the user returns from the app to core-front
      And I pass on the DCMAW callback
      Then I get an 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get an 'pyi-no-match' page response

    Scenario: MAM journey no compatible smartphone continues to other methods
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit a 'neither' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit an 'neither' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-multiple-doc-check' page response with context 'nino'

    Scenario: MAM journey detected iphone
      When I submit an 'mobileDownloadIphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'

    Scenario: MAM journey detected iphone - invalid OS version
      When I submit an 'appTriageSmartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'

    Scenario: MAM journey detected android
      When I submit an 'mobileDownloadAndroid' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'android'

    Scenario: DAD journey no compatible smartphone continues to other methods
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit a 'neither' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-multiple-doc-check' page response with context 'nino'

  Rule: No photo ID
    Scenario: Strategic app no photo ID goes to F2F
      Given I activate the 'strategicApp' feature set
      When I start a new 'low-confidence' journey
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'prove-identity-no-photo-id' page response with context 'nino'
