package uk.gov.di.ipv.core.library.helpers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.domain.SharedAttributesResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.helpers.AuthorizationRequestHelper.SHARED_CLAIMS;

@ExtendWith(MockitoExtension.class)
class AuthorizationRequestHelperTest {

    public static final String CLIENT_ID_FIELD = "client_id";
    public static final String IPV_CLIENT_ID_VALUE = "testClientId";
    public static final String AUDIENCE = "Audience";
    public static final String IPV_TOKEN_TTL = "900";
    public static final String CORE_FRONT_CALLBACK_URL = "callbackUri";
    public static final String CRI_ID = "cri_id";
    private final SharedAttributesResponse sharedAttributes =
            new SharedAttributesResponse(
                    Set.of(new Name(List.of(new NameParts("Dan", "first_name")))),
                    Set.of(new BirthDate("2011-01-01")),
                    Set.of(new Address()));

    private ECDSASigner signer;

    @Mock JWSSigner jwsSigner;

    @BeforeEach
    void setUp() throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException {
        signer = new ECDSASigner(getPrivateKey());
    }

    @Test
    void shouldCreateAuthorizationRequestWithCorrectClaims()
            throws JOSEException, ParseException, HttpResponseExceptionWithErrorBody {
        SignedJWT result =
                AuthorizationRequestHelper.createJWTWithSharedClaims(
                        sharedAttributes,
                        signer,
                        CRI_ID,
                        IPV_CLIENT_ID_VALUE,
                        AUDIENCE,
                        IPV_TOKEN_TTL,
                        CORE_FRONT_CALLBACK_URL);
        assertEquals(IPV_CLIENT_ID_VALUE, result.getJWTClaimsSet().getIssuer());
        assertEquals(IPV_CLIENT_ID_VALUE, result.getJWTClaimsSet().getSubject());
        assertEquals(AUDIENCE, result.getJWTClaimsSet().getAudience().get(0));
        assertEquals(sharedAttributes, result.getJWTClaimsSet().getClaims().get(SHARED_CLAIMS));
        assertEquals(
                IPV_CLIENT_ID_VALUE, result.getJWTClaimsSet().getClaims().get(CLIENT_ID_FIELD));
        assertEquals(
                String.format("%s?id=%s", CORE_FRONT_CALLBACK_URL, CRI_ID),
                result.getJWTClaimsSet().getClaims().get("redirect_uri"));
        assertTrue(result.verify(new ECDSAVerifier(ECKey.parse(EC_PUBLIC_JWK))));
    }

    @Test
    void shouldNotReturnSharedClaimsIfSharedClaimsMapIsEmpty()
            throws ParseException, HttpResponseExceptionWithErrorBody {
        SignedJWT result =
                AuthorizationRequestHelper.createJWTWithSharedClaims(
                        null,
                        signer,
                        CRI_ID,
                        IPV_CLIENT_ID_VALUE,
                        AUDIENCE,
                        IPV_TOKEN_TTL,
                        CORE_FRONT_CALLBACK_URL);
        assertNull(result.getJWTClaimsSet().getClaims().get(SHARED_CLAIMS));
    }

    @Test
    void shouldThrowExceptionWhenUnableToSignJwt() {
        HttpResponseExceptionWithErrorBody exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                AuthorizationRequestHelper.createJWTWithSharedClaims(
                                        null,
                                        jwsSigner,
                                        CRI_ID,
                                        IPV_CLIENT_ID_VALUE,
                                        AUDIENCE,
                                        IPV_TOKEN_TTL,
                                        CORE_FRONT_CALLBACK_URL));
        assertEquals(500, exception.getResponseCode());
        assertEquals("Failed to sign Shared Attributes", exception.getErrorReason());
    }

    @Test
    void shouldThrowExceptionWhenUnableToBuildRedirectionUri() {
        HttpResponseExceptionWithErrorBody exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                AuthorizationRequestHelper.createJWTWithSharedClaims(
                                        null,
                                        jwsSigner,
                                        CRI_ID,
                                        IPV_CLIENT_ID_VALUE,
                                        AUDIENCE,
                                        IPV_TOKEN_TTL,
                                        "[[]]]][[["));
        assertEquals(500, exception.getResponseCode());
        assertEquals("Failed to build Core Front Callback Url", exception.getErrorReason());
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
