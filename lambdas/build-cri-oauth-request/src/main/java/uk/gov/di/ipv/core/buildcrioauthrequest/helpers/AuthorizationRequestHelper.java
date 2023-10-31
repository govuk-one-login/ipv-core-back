package uk.gov.di.ipv.core.buildcrioauthrequest.helpers;

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
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.EvidenceRequest;
import uk.gov.di.ipv.core.library.domain.NinoSharedClaimsResponseDto;
import uk.gov.di.ipv.core.library.domain.SharedClaimsResponse;
import uk.gov.di.ipv.core.library.domain.SharedClaimsResponseDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.JWT_TTL_SECONDS;

public class AuthorizationRequestHelper {

    private static final String SHARED_CLAIMS = "shared_claims";

    private static final String EVIDENCE_REQUESTED = "evidence_requested";

    private static final String CONTEXT = "context";

    private AuthorizationRequestHelper() {}

    public static SignedJWT createSignedJWT(
            SharedClaimsResponse sharedClaims,
            JWSSigner signer,
            CredentialIssuerConfig credentialIssuerConfig,
            ConfigService configService,
            String oauthState,
            String userId,
            String govukSigninJourneyId,
            EvidenceRequest evidence,
            String context)
            throws HttpResponseExceptionWithErrorBody {
        Instant now = Instant.now();

        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();

        JWTClaimsSet authClaimsSet =
                new AuthorizationRequest.Builder(
                                ResponseType.CODE,
                                new ClientID(credentialIssuerConfig.getClientId()))
                        .redirectionURI(credentialIssuerConfig.getClientCallbackUrl())
                        .state(new State(oauthState))
                        .build()
                        .toJWTClaimsSet();

        JWTClaimsSet.Builder claimsSetBuilder =
                new JWTClaimsSet.Builder(authClaimsSet)
                        .audience(credentialIssuerConfig.getComponentId())
                        .issuer(configService.getSsmParameter(COMPONENT_ID))
                        .issueTime(Date.from(now))
                        .expirationTime(
                                Date.from(
                                        now.plus(
                                                Long.parseLong(
                                                        configService.getSsmParameter(
                                                                JWT_TTL_SECONDS)),
                                                ChronoUnit.SECONDS)))
                        .notBeforeTime(Date.from(now))
                        .subject(userId)
                        .claim("govuk_signin_journey_id", govukSigninJourneyId);

        if (Objects.nonNull(sharedClaims)) {
            if (sharedClaims.getEmailAddress() != null) {
                claimsSetBuilder.claim(SHARED_CLAIMS, sharedClaims);
            } else if (!sharedClaims.getSocialSecurityRecord().isEmpty()) {
                NinoSharedClaimsResponseDto response =
                        new NinoSharedClaimsResponseDto(
                                sharedClaims.getName(),
                                sharedClaims.getBirthDate(),
                                sharedClaims.getAddress(),
                                sharedClaims.getSocialSecurityRecord());
                claimsSetBuilder.claim(SHARED_CLAIMS, response);
            } else {
                SharedClaimsResponseDto response =
                        new SharedClaimsResponseDto(
                                sharedClaims.getName(),
                                sharedClaims.getBirthDate(),
                                sharedClaims.getAddress());
                claimsSetBuilder.claim(SHARED_CLAIMS, response);
            }
        }

        if (Objects.nonNull(evidence)) {
            claimsSetBuilder.claim(EVIDENCE_REQUESTED, evidence);
        }

        if (Objects.nonNull(context) && !context.isEmpty()) {
            claimsSetBuilder.claim(CONTEXT, context);
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
}
