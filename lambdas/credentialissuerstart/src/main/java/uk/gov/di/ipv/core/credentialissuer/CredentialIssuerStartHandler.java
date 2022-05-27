package uk.gov.di.ipv.core.credentialissuer;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.credentialissuer.domain.CriDetails;
import uk.gov.di.ipv.core.credentialissuer.domain.CriResponse;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.SharedClaims;
import uk.gov.di.ipv.core.library.domain.SharedClaimsResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.AuthorizationRequestHelper;
import uk.gov.di.ipv.core.library.helpers.KmsEs256Signer;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.text.ParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;

public class CredentialIssuerStartHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(CredentialIssuerStartHandler.class);

    public static final String CRI_ID = "criId";
    public static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";
    public static final int BAD_REQUEST = 400;
    public static final int OK = 200;
    public static final String SHARED_CLAIMS = "shared_claims";

    private final ObjectMapper mapper = new ObjectMapper();

    private final ConfigurationService configurationService;
    private final UserIdentityService userIdentityService;
    private final JWSSigner signer;
    private final AuditService auditService;
    private final IpvSessionService ipvSessionService;

    public CredentialIssuerStartHandler(
            ConfigurationService configurationService,
            UserIdentityService userIdentityService,
            JWSSigner signer,
            AuditService auditService,
            IpvSessionService ipvSessionService) {
        this.configurationService = configurationService;
        this.userIdentityService = userIdentityService;
        this.signer = signer;
        this.auditService = auditService;
        this.ipvSessionService = ipvSessionService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CredentialIssuerStartHandler() {
        this.configurationService = new ConfigurationService();
        this.userIdentityService = new UserIdentityService(configurationService);
        this.signer = new KmsEs256Signer(configurationService.getSigningKeyId());
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
        this.ipvSessionService = new IpvSessionService(configurationService);
    }

    @Override
    @Tracing
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        Map<String, String> pathParameters = input.getPathParameters();

        var errorResponse = validate(pathParameters);
        if (errorResponse.isPresent()) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(400, errorResponse.get());
        }

        CredentialIssuerConfig credentialIssuerConfig =
                getCredentialIssuerConfig(pathParameters.get(CRI_ID));

        if (credentialIssuerConfig == null) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    400, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
        }

        try {
            String ipvSessionId = getIpvSessionId(input.getHeaders());
            UUID oauthState = UUID.randomUUID();
            JWEObject jweObject = signEncryptJar(credentialIssuerConfig, ipvSessionId, oauthState);

            CriResponse criResponse = getCriResponse(credentialIssuerConfig, jweObject);

            persistOauthState(ipvSessionId, credentialIssuerConfig.getId(), oauthState);

            auditService.sendAuditEvent(AuditEventTypes.IPV_REDIRECT_TO_CRI, null);

            return ApiGatewayResponseGenerator.proxyJsonResponse(OK, criResponse);
        } catch (HttpResponseExceptionWithErrorBody exception) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    exception.getResponseCode(), exception.getErrorBody());
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        } catch (ParseException | JOSEException e) {
            LOGGER.error("Failed to parse encryption public JWK: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    private CriResponse getCriResponse(
            CredentialIssuerConfig credentialIssuerConfig, JWEObject jweObject) {
        return new CriResponse(
                new CriDetails(
                        credentialIssuerConfig.getId(),
                        credentialIssuerConfig.getIpvClientId(),
                        credentialIssuerConfig.getAuthorizeUrl().toString(),
                        jweObject.serialize()));
    }

    private JWEObject signEncryptJar(
            CredentialIssuerConfig credentialIssuerConfig, String ipvSessionId, UUID oauthState)
            throws HttpResponseExceptionWithErrorBody, ParseException, JOSEException {
        SharedClaimsResponse sharedClaimsResponse = getSharedAttributes(ipvSessionId);
        SignedJWT signedJWT =
                getSignedJWT(
                        credentialIssuerConfig,
                        oauthState,
                        sharedClaimsResponse,
                        ipvSessionService
                                .getIpvSession(ipvSessionId)
                                .getClientSessionDetails()
                                .getUserId());

        RSAEncrypter rsaEncrypter =
                new RSAEncrypter(credentialIssuerConfig.getJarEncryptionPublicJwk());
        return AuthorizationRequestHelper.createJweObject(rsaEncrypter, signedJWT);
    }

    private SignedJWT getSignedJWT(
            CredentialIssuerConfig credentialIssuerConfig,
            UUID oauthState,
            SharedClaimsResponse sharedClaimsResponse,
            String userId)
            throws HttpResponseExceptionWithErrorBody {
        return AuthorizationRequestHelper.createSignedJWT(
                sharedClaimsResponse,
                signer,
                credentialIssuerConfig,
                configurationService,
                oauthState,
                userId);
    }

    @Tracing
    private Optional<ErrorResponse> validate(Map<String, String> pathParameters) {
        if (pathParameters == null || StringUtils.isBlank(pathParameters.get(CRI_ID))) {
            return Optional.of(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
        }
        return Optional.empty();
    }

    @Tracing
    private CredentialIssuerConfig getCredentialIssuerConfig(String criId) {
        return configurationService.getCredentialIssuer(criId);
    }

    @Tracing
    private SharedClaimsResponse getSharedAttributes(String ipvSessionId)
            throws HttpResponseExceptionWithErrorBody {
        List<String> credentials = userIdentityService.getUserIssuedCredentials(ipvSessionId);

        Set<SharedClaims> sharedAttributes = new HashSet<>();
        for (String credential : credentials) {
            try {
                JsonNode credentialSubject =
                        mapper.readTree(SignedJWT.parse(credential).getPayload().toString())
                                .path(VC_CLAIM)
                                .path(VC_CREDENTIAL_SUBJECT);
                if (credentialSubject.isMissingNode()) {
                    LOGGER.error("Credential subject missing from verified credential");
                    throw new HttpResponseExceptionWithErrorBody(
                            500, ErrorResponse.CREDENTIAL_SUBJECT_MISSING);
                }
                sharedAttributes.add(
                        mapper.readValue(credentialSubject.toString(), SharedClaims.class));
            } catch (JsonProcessingException e) {
                LOGGER.error("Failed to get Shared Attributes: {}", e.getMessage());
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.FAILED_TO_GET_SHARED_ATTRIBUTES);
            } catch (ParseException e) {
                LOGGER.error("Failed to parse issued credentials: {}", e.getMessage());
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
            }
        }
        return SharedClaimsResponse.from(sharedAttributes);
    }

    @Tracing
    private String getIpvSessionId(Map<String, String> headers)
            throws HttpResponseExceptionWithErrorBody {
        String ipvSessionId = RequestHelper.getHeaderByKey(headers, IPV_SESSION_ID_HEADER_KEY);
        if (ipvSessionId == null) {
            LOGGER.error("{} not present in header", IPV_SESSION_ID_HEADER_KEY);
            throw new HttpResponseExceptionWithErrorBody(
                    BAD_REQUEST, ErrorResponse.MISSING_IPV_SESSION_ID);
        }
        return ipvSessionId;
    }

    @Tracing
    private void persistOauthState(String ipvSessionId, String criId, UUID oauthState) {
        IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
        CredentialIssuerSessionDetailsDto credentialIssuerSessionDetailsDto =
                new CredentialIssuerSessionDetailsDto(criId, oauthState.toString());
        ipvSessionItem.setCredentialIssuerSessionDetails(credentialIssuerSessionDetailsDto);
        ipvSessionService.updateIpvSession(ipvSessionItem);
    }
}
