@Build @InitialisesDCMAWSessionState
Feature: M2B Strategic App Journeys

  Rule: UK user
    Background: Start journey
      Given I activate the 'strategicApp' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
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
      Then I get a 'P2' identity

    Scenario: Polling returns 404 until CRI received
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      # And the user returns from the app to core-front
      When I pass on the DCMAW callback
      Then I get an 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '404'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'

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
      And I start a new 'medium-confidence' journey
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
      Then I get an 'page-multiple-doc-check' page response

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

    Scenario: MAM journey abandoned without a VC
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces an 'access_denied' error response
      # This will probably need to change once the polling is working
      And I pass on the DCMAW callback
      Then I get a 'check-mobile-app-result' page response
      When I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get a 'page-multiple-doc-check' page response

    Scenario: MAM journey detected iphone
      When I submit an 'mobileDownloadIphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'

    Scenario: MAM journey detected iphone - invalid OS version
      When I submit an 'appTriageSmartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'

    Scenario: MAM journey declared android
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'android' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'android'

    Scenario: MAM journey detected android
      When I submit an 'mobileDownloadAndroid' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'android'

    Scenario: MAM journey no compatible smartphone
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit a 'neither' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit an 'neither' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-multiple-doc-check' page response

    Scenario: Happy path DAD journey iphone
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-desktop-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
      And I poll for async DCMAW credential receipt
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
      Then I get a 'P2' identity

    Scenario: Happy path DAD journey android
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit an 'android' event
      Then I get a 'pyi-triage-desktop-download-app' page response with context 'android'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
      And I poll for async DCMAW credential receipt
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
      Then I get a 'P2' identity

    Scenario: DAD journey iphone fails with ci and goes to no match page
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-desktop-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC with a CI
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get an 'pyi-no-match' page response

    Scenario: DAD journey credential fails with fails with no ci and continues to other methods
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-desktop-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC
      And I poll for async DCMAW credential receipt
      Then the poll returns a '201'
      When I submit the returned journey event
      Then I get an 'page-multiple-doc-check' page response

    Scenario: DAD journey no compatible smartphone
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit a 'neither' event
      Then I get a 'pyi-triage-buffer' page response
      When I submit an 'anotherWay' event
      Then I get a 'page-multiple-doc-check' page response

    Scenario: Strategic app uk address user wants to go back over identify-device page
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'back' event
      Then I get a 'page-ipv-identity-document-start' page response

  Rule: No photo ID
    Scenario: Strategic app no photo ID goes to F2F
      Given I activate the 'strategicApp' feature set
      When I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'uk' event
      Then I get a 'page-ipv-identity-document-start' page response
      When I submit an 'end' event
      Then I get a 'page-ipv-identity-postoffice-start' page response

  Rule: International user
    Background: Start journey
      Given I activate the 'strategicApp' feature sets
      And I start a new 'medium-confidence' journey
      Then I get a 'live-in-uk' page response
      When I submit a 'international' event
      Then I get a 'non-uk-passport' page response

    Scenario: Happy path successful P2 identity
      When I submit a 'next' event
      Then I get a 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'smartphone' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
      When I submit an 'iphone' event
      Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
      When the async DCMAW CRI produces a 'kenneth-passport-valid' VC
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
      Then I get a 'P2' identity

    Scenario: Strategic app non-uk address user abandons due to no biometric passport
      When I submit a 'abandon' event
      Then I get a 'non-uk-no-passport' page response
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

    Scenario: Strategic app non-uk address user abandons due to no biometric passport then returns
      When I submit a 'abandon' event
      Then I get a 'non-uk-no-passport' page response
      When I submit a 'useApp' event
      Then I get a 'identify-device' page response

    Scenario: Strategic app non-uk address user retries with app
      When I submit a 'next' event
      Then I get a 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit a 'neither' event
      Then I get a 'non-uk-no-app-options' page response
      When I submit a 'useApp' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'

    Scenario: Strategic app non-uk address user wants to prove identity another way from download page
      When I submit a 'next' event
      Then I get a 'identify-device' page response
      When I submit an 'appTriage' event
      Then I get a 'pyi-triage-select-device' page response
      When I submit a 'computer-or-tablet' event
      Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
      When I submit a 'iphone' event
      Then I get a 'pyi-triage-desktop-download-app' page response with context 'iphone'
      When I submit a 'preferNoApp' event
      Then I get a 'non-uk-no-app-options' page response
      # Change their mind and go back
      When I submit a 'useApp' event
      Then I get a 'pyi-triage-desktop-download-app' page response with context 'iphone'
      # Decide to abandon again
      When I submit a 'preferNoApp' event
      Then I get a 'non-uk-no-app-options' page response
      When I submit a 'returnToRp' event
      Then I get an OAuth response
      When I use the OAuth response to get my identity
      Then I get a 'P0' identity

  Scenario: Discount PENDING_RETURN VCs when no pending record
    Given the subject already has the following credentials
      | CRI        | scenario               |
      | dcmawAsync | kenneth-passport-valid |
      | address    | kenneth-current        |
      | fraud      | kenneth-score-2        |

    When I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'uk' event
    Then I get a 'page-ipv-identity-document-start' page response
