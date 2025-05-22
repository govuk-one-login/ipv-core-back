package uk.gov.di.ipv.core.buildcrioauthrequest.helpers;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.buildcrioauthrequest.domain.SharedClaims;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.EvidenceRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.CoreSigner;

import java.time.Instant;
import java.util.Date;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.JWT_TTL_SECONDS;
import static uk.gov.di.ipv.core.library.helpers.JwtHelper.createSignedJwt;

public class AuthorizationRequestHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String SHARED_CLAIMS = "shared_claims";
    private static final String EVIDENCE_REQUESTED = "evidence_requested";
    private static final String CONTEXT = "context";

    private AuthorizationRequestHelper() {}

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public static SignedJWT createSignedJWT(
            SharedClaims sharedClaims,
            CoreSigner signer,
            OauthCriConfig oauthCriConfig,
            ConfigService configService,
            String oauthState,
            String userId,
            String govukSigninJourneyId,
            EvidenceRequest evidenceRequest,
            String context)
            throws HttpResponseExceptionWithErrorBody {
        Instant now = Instant.now();

        JWTClaimsSet authClaimsSet =
                new AuthorizationRequest.Builder(
                                ResponseType.CODE, new ClientID(oauthCriConfig.getClientId()))
                        .redirectionURI(oauthCriConfig.getClientCallbackUrl())
                        .state(new State(oauthState))
                        .build()
                        .toJWTClaimsSet();

        JWTClaimsSet.Builder claimsSetBuilder =
                new JWTClaimsSet.Builder(authClaimsSet)
                        .audience(oauthCriConfig.getComponentId())
                        .issuer(configService.getParameter(COMPONENT_ID))
                        .issueTime(Date.from(now))
                        .expirationTime(
                                Date.from(
                                        now.plusSeconds(
                                                configService.getLongParameter(JWT_TTL_SECONDS))))
                        .notBeforeTime(Date.from(now))
                        .subject(userId)
                        .claim("govuk_signin_journey_id", govukSigninJourneyId);

        if (Objects.nonNull(sharedClaims)) {
            claimsSetBuilder.claim(SHARED_CLAIMS, sharedClaims.toMapWithNoNulls());
        }

        if (Objects.nonNull(evidenceRequest)) {
            claimsSetBuilder.claim(EVIDENCE_REQUESTED, evidenceRequest.toMapWithNoNulls());
        }

        if (Objects.nonNull(context)) {
            claimsSetBuilder.claim(CONTEXT, context);
        }

        try {
            return createSignedJwt(claimsSetBuilder.build(), signer);
        } catch (JOSEException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to sign shared attributes", e));
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.FAILED_TO_SIGN_SHARED_ATTRIBUTES);
        }
    }

    public static JWEObject createJweObject(
            RSAEncrypter rsaEncrypter, SignedJWT signedJWT, String keyId)
            throws HttpResponseExceptionWithErrorBody {
        try {
            var jweHeaderBuilder =
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                            .contentType("JWT");

            if (keyId != null) {
                jweHeaderBuilder.keyID(keyId);
            }

            JWEObject jweObject = new JWEObject(jweHeaderBuilder.build(), new Payload(signedJWT));
            jweObject.encrypt(rsaEncrypter);
            return jweObject;
        } catch (JOSEException e) {
            throw new HttpResponseExceptionWithErrorBody(500, ErrorResponse.FAILED_TO_ENCRYPT_JWT);
        }
    }
}
