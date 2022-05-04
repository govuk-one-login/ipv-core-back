package uk.gov.di.ipv.core.library.helpers;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.http.client.utils.URIBuilder;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.SharedAttributesResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Objects;

public class AuthorizationRequestHelper {

    public static final String SHARED_CLAIMS = "shared_claims";
    public static final String PARAM_ID = "id";

    private AuthorizationRequestHelper() {}

    public static SignedJWT createSignedJWT(
            SharedAttributesResponse sharedClaims,
            JWSSigner signer,
            String criId,
            String ipvClientId,
            String audience,
            String ipvTokenTtl,
            String coreFrontCallbackUrl)
            throws HttpResponseExceptionWithErrorBody {
        Instant now = Instant.now();

        ClientID clientID = new ClientID(ipvClientId);

        URI redirectionURI = getRedirectionURI(criId, coreFrontCallbackUrl);

        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();

        JWTClaimsSet authClaimsSet =
                new AuthorizationRequest.Builder(ResponseType.CODE, clientID)
                        .redirectionURI(redirectionURI)
                        .state(new State("read"))
                        .build()
                        .toJWTClaimsSet();

        JWTClaimsSet.Builder claimsSetBuilder =
                new JWTClaimsSet.Builder(authClaimsSet)
                        .audience(audience)
                        .issuer(ipvClientId)
                        .issueTime(Date.from(now))
                        .expirationTime(
                                Date.from(
                                        now.plus(Long.parseLong(ipvTokenTtl), ChronoUnit.SECONDS)))
                        .notBeforeTime(Date.from(now))
                        .subject(ipvClientId);

        if (Objects.nonNull(sharedClaims)) {
            claimsSetBuilder.claim(SHARED_CLAIMS, sharedClaims);
        }

        SignedJWT signedJWT = new SignedJWT(header, claimsSetBuilder.build());
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.FAILED_TO_SIGN_SHARED_ATTRIBUTES);
        }

        return signedJWT;
    }

    public static JWEObject createJweObject(RSAEncrypter rsaEncrypter, SignedJWT signedJWT)
            throws HttpResponseExceptionWithErrorBody {
        try {
            JWEObject jweObject =
                    new JWEObject(
                            new JWEHeader.Builder(
                                            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                    .contentType("JWT")
                                    .build(),
                            new Payload(signedJWT));
            jweObject.encrypt(rsaEncrypter);
            return jweObject;
        } catch (JOSEException e) {
            throw new HttpResponseExceptionWithErrorBody(500, ErrorResponse.FAILED_TO_ENCRYPT_JWT);
        }
    }

    private static URI getRedirectionURI(String criId, String coreFrontCallbackUrl)
            throws HttpResponseExceptionWithErrorBody {
        try {
            URIBuilder uriBuilder =
                    new URIBuilder(coreFrontCallbackUrl).addParameter(PARAM_ID, criId);
            return uriBuilder.build();
        } catch (URISyntaxException e) {
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.FAILED_TO_BUILD_CORE_FRONT_CALLBACK_URL);
        }
    }
}
