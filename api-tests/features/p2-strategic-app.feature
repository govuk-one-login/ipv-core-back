@Build @InitialisesDCMAWSessionState
Feature: M2B Strategic App Journeys

  Scenario: MAM journey declared iphone
    Given I activate the 'strategicApp' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
    When the DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get an 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    And I submit the returned journey event
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

  Scenario: MAM journey pending credential
    Given I activate the 'strategicApp' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'identify-device' page response
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
    When the DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
    When I poll for async DCMAW credential receipt
    Then the poll returns a '200'

  Scenario: MAM journey cross-browser scenario
    Given I activate the 'strategicApp' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
    When the DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'success' VC
    # And the user returns from the app to core-front
    Then I pass on the DCMAW callback in a separate session
    # Mocking the time for the user to log back in
    And I poll for async DCMAW credential receipt
    When I start a new 'medium-confidence' journey
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

  Scenario: MAM journey credential fails with no ci
    Given I activate the 'strategicApp' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
    When the DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'fail' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get an 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    And I submit the returned journey event
    Then I get an 'page-multiple-doc-check' page response

  Scenario: MAM journey credential fails with ci
    Given I activate the 'strategicApp' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'
    When the DCMAW CRI produces a 'kennethD' 'ukChippedPassport' 'failWithCi' VC
    # And the user returns from the app to core-front
    And I pass on the DCMAW callback
    Then I get an 'check-mobile-app-result' page response
    When I poll for async DCMAW credential receipt
    Then the poll returns a '201'
    And I submit the returned journey event
    Then I get an 'pyi-technical' page response

  Scenario: MAM journey detected iphone
    Given I activate the 'strategicApp' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriageIphone' event
    Then I get a 'pyi-triage-mobile-confirm' page response with context 'iphone'
    When I submit an 'next' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'iphone'

  Scenario: MAM journey declared android
    Given I activate the 'strategicApp' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'smartphone' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'mam'
    When I submit an 'android' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'android'

  Scenario: MAM journey detected android
    Given I activate the 'strategicApp' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriageAndroid' event
    Then I get a 'pyi-triage-mobile-confirm' page response with context 'android'
    When I submit an 'next' event
    Then I get a 'pyi-triage-mobile-download-app' page response with context 'android'

  Scenario: MAM journey no compatible smartphone
    Given I activate the 'strategicApp' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'identify-device' page response
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

  Scenario: DAD journey iphone
    Given I activate the 'strategicApp' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit an 'iphone' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context 'iphone'

  Scenario: DAD journey android
    Given I activate the 'strategicApp' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit an 'android' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context 'android'

  Scenario: DAD journey no compatible smartphone
    Given I activate the 'strategicApp' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'appTriage' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit a 'neither' event
    Then I get a 'pyi-triage-buffer' page response
    When I submit an 'anotherWay' event
    Then I get a 'page-multiple-doc-check' page response

  Scenario: Strategic app no photo ID goes to F2F
    Given I activate the 'strategicApp' feature set
    When I start a new 'medium-confidence' journey
    Then I get a 'page-ipv-identity-document-start' page response
    When I submit an 'end' event
    Then I get a 'page-ipv-identity-postoffice-start' page response

  Scenario: Strategic app non-uk address user gets to download app
    Given I activate the 'internationalAddress,strategicApp' feature sets
    And I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'international' event
    Then I get a 'non-uk-passport' page response
    When I submit a 'next' event
    Then I get a 'identify-device' page response
    When I submit an 'appTriage' event
    Then I get a 'pyi-triage-select-device' page response
    When I submit a 'computer-or-tablet' event
    Then I get a 'pyi-triage-select-smartphone' page response with context 'dad'
    When I submit a 'iphone' event
    Then I get a 'pyi-triage-desktop-download-app' page response with context 'iphone'

  Scenario: Strategic app non-uk address user abandons due to no biometric passport
    Given I activate the 'internationalAddress,strategicApp' feature sets
    And I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'international' event
    Then I get a 'non-uk-passport' page response
    When I submit a 'abandon' event
    Then I get a 'non-uk-no-passport' page response
    When I submit a 'returnToRp' event
    Then I get an OAuth response
    When I use the OAuth response to get my identity

  Scenario: Strategic app non-uk address user abandons due to no biometric passport then returns
    Given I activate the 'internationalAddress,strategicApp' feature sets
    And I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'international' event
    Then I get a 'non-uk-passport' page response
    When I submit a 'abandon' event
    Then I get a 'non-uk-no-passport' page response
    When I submit a 'useApp' event
    Then I get a 'identify-device' page response

  Scenario: Strategic app non-uk address user retries with app
    Given I start a new 'medium-confidence' journey
    And I activate the 'internationalAddress,strategicApp' feature sets
    And I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'international' event
    Then I get a 'non-uk-passport' page response
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
    Given I start a new 'medium-confidence' journey
    And I activate the 'internationalAddress,strategicApp' feature sets
    And I start a new 'medium-confidence' journey
    Then I get a 'live-in-uk' page response
    When I submit a 'international' event
    Then I get a 'non-uk-passport' page response
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
