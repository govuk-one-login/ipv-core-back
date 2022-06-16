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
import uk.gov.di.ipv.core.library.domain.SharedClaimsResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.AUDIENCE_FOR_CLIENTS;

public class AuthorizationRequestHelper {

    public static final String SHARED_CLAIMS = "shared_claims";
    public static final String PARAM_ID = "id";

    private AuthorizationRequestHelper() {}

    public static SignedJWT createSignedJWT(
            SharedClaimsResponse sharedClaims,
            JWSSigner signer,
            CredentialIssuerConfig credentialIssuerConfig,
            ConfigurationService configurationService,
            UUID oauthState,
            String userId)
            throws HttpResponseExceptionWithErrorBody {
        Instant now = Instant.now();

        String criId = credentialIssuerConfig.getId();

        URI redirectionURI =
                getRedirectionURI(criId, configurationService.getCoreFrontCallbackUrl());

        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();

        JWTClaimsSet authClaimsSet =
                new AuthorizationRequest.Builder(
                                ResponseType.CODE,
                                new ClientID(credentialIssuerConfig.getIpvClientId()))
                        .redirectionURI(redirectionURI)
                        .state(new State(oauthState.toString()))
                        .build()
                        .toJWTClaimsSet();

        JWTClaimsSet.Builder claimsSetBuilder =
                new JWTClaimsSet.Builder(authClaimsSet)
                        .audience(credentialIssuerConfig.getAudienceForClients())
                        .issuer(configurationService.get(AUDIENCE_FOR_CLIENTS))
                        .issueTime(Date.from(now))
                        .expirationTime(
                                Date.from(
                                        now.plus(
                                                Long.parseLong(
                                                        configurationService.getIpvTokenTtl()),
                                                ChronoUnit.SECONDS)))
                        .notBeforeTime(Date.from(now))
                        .subject(userId);

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
