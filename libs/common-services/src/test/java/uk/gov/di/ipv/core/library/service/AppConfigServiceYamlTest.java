package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.lambda.powertools.parameters.AppConfigProvider;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.dto.CriConfig;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class AppConfigServiceYamlTest {
    private static final String TEST_RAW_PARAMETERS =
            """
        core:
          self:
            configFormat: yaml
            componentId: "test-component-id"
            bearerTokenTtl: 1800
            someStringList: "a,list,of,strings"
          credentialIssuers:
            address:
              activeConnection: main
              connections:
                main:
                  componentId: main-issuer
                  authorizeUrl: https://testAuthoriseUrl
                  tokenUrl: https://testTokenUrl
                  credentialUrl: https://testCredentialUrl
                  clientId: ipv-core-test
                  signingKey: '{\\"kty\\":\\"EC\\",\\"kid\\":\\"test-fixtures-ec-key\\",\\"use\\":\\"sig\\",\\"d\\":\\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\\",\\"crv\\":\\"P-256\\",\\"x\\":\\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\\",\\"y\\":\\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\\"}' # pragma: allowlist secret
                  encryptionKey: '{\\"kty\\":\\"RSA\\",\\"e\\":\\"AQAB\\",\\"use\\":\\"enc\\",\\"kid\\":\\"nfwejnfwefcojwnk\\",\\"n\\":\\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q\\"}' # pragma: allowlist secret
                  clientCallbackUrl: https://testClientCallBackUrl
                  requiresApiKey: true
                  requiresAdditionalEvidence: false
                  jwksUrl: https://testWellKnownUrl
                stub:
                  componentId: stub-issuer
              historicSigningKeys: '{"kty":"EC","crv":"P-256","x":"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM","y":"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04"}/{"kty":"EC","crv":"P-256","x":"MjTFSolNjla11Dl8Zk9UpcpnMyWumfjIbO1E-0c8v-E","y":"xTdKNukh5sOvMgNTKjo0hVYNNcAS-N7X1R1S0cjllTo"}' # pragma: allowlist secret
            dcmaw:
              activeConnection: test
              connections:
                test:
                  componentId: dcmaw-issuer
          featureFlags:
            testFeatureFlag: false
            anotherFeatureFlag: true
          features:
            testFeature:
              featureFlags:
                testFeatureFlag: true
              self:
                componentId: "alternate-component-id"
          cimit:
            config:
              NEEDS-ALTERNATE-DOC:
                - event: /journey/alternate-doc-invalid-dl
                  document: drivingPermit
          clients:
            testClient:
              validRedirectUrls: a,list,of,strings
    """;
    @Mock Cri criMock;
    @Mock AppConfigProvider appConfigProvider;
    @Mock SecretsProvider secretsProvider;
    AppConfigService configService;

    @BeforeEach
    void setUp() {
        configService = new AppConfigService(appConfigProvider, secretsProvider);
        lenient().when(appConfigProvider.get(any())).thenReturn(TEST_RAW_PARAMETERS);
    }

    // CIMIT config

    @Test
    void shouldFetchCimitConfig() throws ConfigException {
        // Act
        var cimitConfig = configService.getCimitConfig();

        // Assert
        assertEquals(
                "/journey/alternate-doc-invalid-dl",
                cimitConfig.get("NEEDS-ALTERNATE-DOC").get(0).event());
        assertEquals("drivingPermit", cimitConfig.get("NEEDS-ALTERNATE-DOC").get(0).document());
    }

    @Test
    void shouldThrowErrorOnInvalidCimitConfig() {
        // Arrange
        var testRawParametersInvalidCimit =
                """
            core:
              self:
                configFormat: yaml
              cimit:
                config:
                  notvalid: at-all
              credentialIssuers:
                address:
                  connections:
                    main:
                      componentId: main-issuer
        """;
        when(appConfigProvider.get(any())).thenReturn(testRawParametersInvalidCimit);
        configService = new AppConfigService(appConfigProvider, secretsProvider);

        // Act & Assert
        assertThrows(ConfigException.class, () -> configService.getCimitConfig());
    }

    // Get CRI by issuer

    @Test
    void shouldReturnIssuerCris() {
        // Act & Assert
        var config = configService.getIssuerCris();

        assertEquals(
                Map.of("stub-issuer", ADDRESS, "main-issuer", ADDRESS, "dcmaw-issuer", DCMAW),
                config);
    }

    // OAuth CRI config

    @Nested
    @DisplayName("credential issuer config")
    class ActiveOauthCriConfig {
        private final OauthCriConfig expectedOauthCriConfig =
                OauthCriConfig.builder()
                        .tokenUrl(URI.create("https://testTokenUrl"))
                        .credentialUrl(URI.create("https://testCredentialUrl"))
                        .authorizeUrl(URI.create("https://testAuthoriseUrl"))
                        .clientId("ipv-core-test")
                        .signingKey(EC_PRIVATE_KEY_JWK)
                        .encryptionKey(RSA_ENCRYPTION_PUBLIC_JWK)
                        .componentId("main-issuer")
                        .clientCallbackUrl(URI.create("https://testClientCallBackUrl"))
                        .requiresApiKey(true)
                        .requiresAdditionalEvidence(false)
                        .jwksUrl(URI.create("https://testWellKnownUrl"))
                        .build();

        @Test
        void getOauthCriActiveConnectionConfigShouldGetCredentialIssuerFromParameterStore() {
            // Act
            var result = configService.getOauthCriActiveConnectionConfig(ADDRESS);

            // Assert
            assertEquals(expectedOauthCriConfig, result);
        }

        @Test
        void getOauthCriConfigShouldGetConfigForCriOauthSessionItem() {
            // Act
            var result =
                    configService.getOauthCriConfig(
                            CriOAuthSessionItem.builder()
                                    .criId(ADDRESS.getId())
                                    .connection("main")
                                    .build());

            // Assert
            assertEquals(expectedOauthCriConfig, result);
        }

        @Test
        void getOauthCriConfigForConnectionShouldGetOauthCriConfig() {
            // Act
            var result = configService.getOauthCriConfigForConnection("main", ADDRESS);

            // Assert
            assertEquals(expectedOauthCriConfig, result);
        }

        @Test
        void getOauthCriConfigForConnectionShouldThrowIfNoCriConfigFound() {
            // Act & Assert
            assertThrows(
                    ConfigParameterNotFoundException.class,
                    () -> configService.getOauthCriConfigForConnection("stub", Cri.PASSPORT));
        }

        @Test
        void getRestCriConfigShouldReturnARestCriConfig() throws URISyntaxException {
            // Act
            var result = configService.getRestCriConfigForConnection("main", ADDRESS);

            // Assert
            assertEquals(
                    RestCriConfig.builder()
                            .credentialUrl(new URI("https://testCredentialUrl"))
                            .requiresApiKey(true)
                            .signingKey(EC_PRIVATE_KEY_JWK)
                            .componentId("main-issuer")
                            .build(),
                    result);
        }

        @Test
        void getCriConfigShouldReturnACriConfig() {
            // Act
            var result = configService.getCriConfig(ADDRESS);

            // Assert
            assertEquals(
                    CriConfig.builder()
                            .signingKey(EC_PRIVATE_KEY_JWK)
                            .componentId("main-issuer")
                            .build(),
                    result);
        }
    }
}
