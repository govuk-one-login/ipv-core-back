package uk.gov.di.ipv.core.issueclientaccesstoken.domain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.oauthkeyservice.OAuthKeyService;

import java.security.PublicKey;
import java.text.ParseException;

import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_JWT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
class OAuthKeyServiceClientCredentialsSelectorTest {
    private static final JWSHeader JWS_HEADER = new JWSHeader(JWSAlgorithm.ES256);
    private static final String TEST_CLIENT_ID = "test-client-id";

    @Mock private OAuthKeyService mockOAuthKeyService;

    @InjectMocks private OAuthKeyServiceClientCredentialsSelector keySelector;

    @Test
    void selectClientSecretsShouldThrow() {
        var clientId = new ClientID(TEST_CLIENT_ID);
        var context = new Context<>();

        assertThrows(
                UnsupportedOperationException.class,
                () -> keySelector.selectClientSecrets(clientId, CLIENT_SECRET_JWT, context));
    }

    @Test
    void selectPublicKeysShouldReturnKeys() throws Exception {
        when(mockOAuthKeyService.getClientSigningKey(TEST_CLIENT_ID, JWS_HEADER))
                .thenReturn(ECKey.parse(TEST_EC_PUBLIC_JWK));

        PublicKey jwkClientPublicKey =
                keySelector
                        .selectPublicKeys(
                                new ClientID(TEST_CLIENT_ID), null, JWS_HEADER, false, null)
                        .get(0);

        assertEquals(ECKey.parse(TEST_EC_PUBLIC_JWK).toECPublicKey(), jwkClientPublicKey);
    }

    @Test
    void selectPublicKeysShouldThrowIfUnsupportedAlgorithm() {
        var exception =
                assertThrows(
                        InvalidClientException.class,
                        () ->
                                keySelector.selectPublicKeys(
                                        new ClientID(TEST_CLIENT_ID),
                                        null,
                                        new JWSHeader(JWSAlgorithm.HS256),
                                        false,
                                        null));

        assertEquals(
                "HS256 algorithm is not supported. Received from client ID 'test-client-id'",
                exception.getMessage());
    }

    @Test
    void selectPublicKeysShouldThrowIfOAuthKeyServiceThrows() throws Exception {
        when(mockOAuthKeyService.getClientSigningKey(eq(TEST_CLIENT_ID), any()))
                .thenThrow(new ParseException("oops", 0));

        assertThrows(
                InvalidClientException.class,
                () ->
                        keySelector.selectPublicKeys(
                                new ClientID(TEST_CLIENT_ID), null, JWS_HEADER, false, null));
    }

    @Test
    void selectPublicKeysShouldThrowIfErrorCastingToPublicKey() throws Exception {
        var mockECKey = mock(ECKey.class);
        when(mockOAuthKeyService.getClientSigningKey(TEST_CLIENT_ID, JWS_HEADER))
                .thenReturn(mockECKey);
        when(mockECKey.toECPublicKey()).thenThrow(new JOSEException("oops"));

        assertThrows(
                InvalidClientException.class,
                () ->
                        keySelector.selectPublicKeys(
                                new ClientID(TEST_CLIENT_ID), null, JWS_HEADER, false, null));
    }
}
