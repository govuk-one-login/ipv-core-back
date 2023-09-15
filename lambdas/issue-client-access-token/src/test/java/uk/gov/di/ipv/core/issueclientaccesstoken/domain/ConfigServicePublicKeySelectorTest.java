package uk.gov.di.ipv.core.issueclientaccesstoken.domain;

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
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_JWT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY;

@ExtendWith(MockitoExtension.class)
class ConfigServicePublicKeySelectorTest {

    @Mock private ConfigService configServiceMock;

    @InjectMocks private ConfigurationServicePublicKeySelector keySelector;

    @Test
    void selectClientSecretsShouldThrow() {
        ClientID clientId = new ClientID("someId");
        Context context = new Context();

        assertThrows(
                UnsupportedOperationException.class,
                () -> keySelector.selectClientSecrets(clientId, CLIENT_SECRET_JWT, context));
    }

    @Test
    void selectPublicKeysShouldReturnKeys() throws Exception {
        when(configServiceMock.getSsmParameter(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY, "jwkClient"))
                .thenReturn(TestFixtures.EC_PUBLIC_JWK);
        when(configServiceMock.getSsmParameter(
                        PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY, "x509Client"))
                .thenReturn(TestFixtures.RSA_PUBLIC_CERT);
        when(configServiceMock.getSsmParameter(
                        PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY, "misconfiguredClient"))
                .thenReturn("some nonsense");

        PublicKey jwkClientPublicKey =
                keySelector
                        .selectPublicKeys(
                                new ClientID("jwkClient"),
                                null,
                                new JWSHeader(JWSAlgorithm.ES256),
                                false,
                                null)
                        .get(0);
        PublicKey x509ClientPublicKey =
                keySelector
                        .selectPublicKeys(
                                new ClientID("x509Client"),
                                null,
                                new JWSHeader(JWSAlgorithm.RS256),
                                false,
                                null)
                        .get(0);

        assertThrows(
                InvalidClientException.class,
                () ->
                        keySelector.selectPublicKeys(
                                new ClientID("misconfiguredClient"),
                                null,
                                new JWSHeader(JWSAlgorithm.ES256),
                                false,
                                null));

        assertEquals(ECKey.parse(TestFixtures.EC_PUBLIC_JWK).toECPublicKey(), jwkClientPublicKey);
        assertEquals(
                CertificateFactory.getInstance("X.509")
                        .generateCertificate(
                                new ByteArrayInputStream(
                                        Base64.getDecoder().decode(TestFixtures.RSA_PUBLIC_CERT)))
                        .getPublicKey(),
                x509ClientPublicKey);
    }

    @Test
    void selectPublicKeysShouldThrowIfUnsupportedAlgorithm() {
        when(configServiceMock.getSsmParameter(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY, "jwkClient"))
                .thenReturn(TestFixtures.EC_PUBLIC_JWK);

        InvalidClientException exception =
                assertThrows(
                        InvalidClientException.class,
                        () ->
                                keySelector.selectPublicKeys(
                                        new ClientID("jwkClient"),
                                        null,
                                        new JWSHeader(JWSAlgorithm.HS256),
                                        false,
                                        null));

        assertEquals(
                "HS256 algorithm is not supported. Received from client ID 'jwkClient'",
                exception.getMessage());
    }

    @Test
    void selectPublicKeysShouldThrowIfKeyMaterialDoesNotMatchAlgo() {
        when(configServiceMock.getSsmParameter(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY, "jwkClient"))
                .thenReturn(TestFixtures.RSA_PUBLIC_CERT);
        when(configServiceMock.getSsmParameter(
                        PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY, "x509Client"))
                .thenReturn(TestFixtures.EC_PUBLIC_JWK);

        assertThrows(
                InvalidClientException.class,
                () ->
                        keySelector.selectPublicKeys(
                                new ClientID("jwkClient"),
                                null,
                                new JWSHeader(JWSAlgorithm.ES256),
                                false,
                                null));
        assertThrows(
                InvalidClientException.class,
                () ->
                        keySelector.selectPublicKeys(
                                new ClientID("x509Client"),
                                null,
                                new JWSHeader(JWSAlgorithm.RS256),
                                false,
                                null));
    }
}
