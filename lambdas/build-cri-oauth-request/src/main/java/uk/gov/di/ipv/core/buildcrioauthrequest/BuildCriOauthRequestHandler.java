package uk.gov.di.ipv.core.buildcrioauthrequest;

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
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.buildcrioauthrequest.domain.CriDetails;
import uk.gov.di.ipv.core.buildcrioauthrequest.domain.CriResponse;
import uk.gov.di.ipv.core.buildcrioauthrequest.helpers.AuthorizationRequestHelper;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.credentialissuer.CredentialIssuerConfigService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.SharedClaims;
import uk.gov.di.ipv.core.library.domain.SharedClaimsResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.kmses256signer.KmsEs256Signer;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.*;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;

public class BuildCriOauthRequestHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String CRI_ID = "criId";
    private static final int OK = 200;
    private static final String DCMAW_CRI_ID = "dcmaw";
    private static final String STUB_DCMAW_CRI_ID = "stubDcmaw";
    private static final JourneyResponse ERROR_JOURNEY = new JourneyResponse("/journey/error");
    public static final String SHARED_CLAIM_ATTR_NAME = "name";
    public static final String SHARED_CLAIM_ATTR_BIRTH_DATE = "birthDate";
    public static final String SHARED_CLAIM_ATTR_ADDRESS = "address";
    public static final String DEFAULT_ALLOWED_SHARED_ATTR = "name,birthDate,address";
    public static final String REGEX_COMMA_SEPARATION = "\\s*,\\s*";

    private final ObjectMapper mapper = new ObjectMapper();
    private final CredentialIssuerConfigService credentialIssuerConfigService;
    private final UserIdentityService userIdentityService;
    private final JWSSigner signer;
    private final AuditService auditService;
    private final IpvSessionService ipvSessionService;
    private final CriOAuthSessionService criOAuthSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final String componentId;

    public BuildCriOauthRequestHandler(
            CredentialIssuerConfigService credentialIssuerConfigService,
            UserIdentityService userIdentityService,
            JWSSigner signer,
            AuditService auditService,
            IpvSessionService ipvSessionService,
            CriOAuthSessionService criOAuthSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService) {

        this.credentialIssuerConfigService = credentialIssuerConfigService;
        this.userIdentityService = userIdentityService;
        this.signer = signer;
        this.auditService = auditService;
        this.ipvSessionService = ipvSessionService;
        this.criOAuthSessionService = criOAuthSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.componentId =
                credentialIssuerConfigService.getSsmParameter(ConfigurationVariable.COMPONENT_ID);
    }

    @ExcludeFromGeneratedCoverageReport
    public BuildCriOauthRequestHandler() {
        this.credentialIssuerConfigService = new CredentialIssuerConfigService();
        this.userIdentityService = new UserIdentityService(credentialIssuerConfigService);
        this.signer = new KmsEs256Signer(credentialIssuerConfigService.getSigningKeyId());
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), credentialIssuerConfigService);
        this.ipvSessionService = new IpvSessionService(credentialIssuerConfigService);
        this.criOAuthSessionService = new CriOAuthSessionService(credentialIssuerConfigService);
        this.clientOAuthSessionDetailsService =
                new ClientOAuthSessionDetailsService(credentialIssuerConfigService);
        this.componentId =
                credentialIssuerConfigService.getSsmParameter(ConfigurationVariable.COMPONENT_ID);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(input);
            String ipAddress = RequestHelper.getIpAddress(input);
            Map<String, String> pathParameters = input.getPathParameters();

            var errorResponse = validate(pathParameters);
            if (errorResponse.isPresent()) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(400, errorResponse.get());
            }

            String criId = pathParameters.get(CRI_ID);
            CredentialIssuerConfig credentialIssuerConfig = getCredentialIssuerConfig(criId);

            if (credentialIssuerConfig == null) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        400, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
            }

            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem = null;
            if (ipvSessionItem.getClientOAuthSessionId() != null) {
                clientOAuthSessionItem =
                        clientOAuthSessionDetailsService.getClientOAuthSession(
                                ipvSessionItem.getClientOAuthSessionId());
            }

            String userId = clientOAuthSessionItem.getUserId();

            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();

            List<VcStatusDto> currentVcStatuses = ipvSessionItem.getCurrentVcStatuses();

            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            String oauthState = SecureTokenHelper.generate();
            JWEObject jweObject =
                    signEncryptJar(
                            credentialIssuerConfig,
                            userId,
                            oauthState,
                            govukSigninJourneyId,
                            currentVcStatuses,
                            criId);

            CriResponse criResponse = getCriResponse(credentialIssuerConfig, jweObject);

            persistOauthState(ipvSessionItem, credentialIssuerConfig.getId(), oauthState);

            persistCriOauthState(oauthState, credentialIssuerConfig.getId());

            AuditEventUser auditEventUser =
                    new AuditEventUser(userId, ipvSessionId, govukSigninJourneyId, ipAddress);
            auditService.sendAuditEvent(
                    new AuditEvent(
                            AuditEventTypes.IPV_REDIRECT_TO_CRI, componentId, auditEventUser));

            var message =
                    new StringMapMessage()
                            .with("lambdaResult", "Successfully generated ipv cri oauth request.")
                            .with("redirectUri", criResponse.getCri().getRedirectUrl());
            LOGGER.info(message);

            return ApiGatewayResponseGenerator.proxyJsonResponse(OK, criResponse);

        } catch (HttpResponseExceptionWithErrorBody e) {
            if (ErrorResponse.MISSING_IPV_SESSION_ID.equals(e.getErrorResponse())) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        e.getResponseCode(), e.getErrorBody());
            }
            LOGGER.error("Failed to create cri JAR because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, ERROR_JOURNEY);
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, ERROR_JOURNEY);
        } catch (ParseException | JOSEException e) {
            LOGGER.error("Failed to parse encryption public JWK: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, ERROR_JOURNEY);
        } catch (URISyntaxException e) {
            LOGGER.error("Failed to construct redirect uri because: {}", e.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    private CriResponse getCriResponse(
            CredentialIssuerConfig credentialIssuerConfig, JWEObject jweObject)
            throws URISyntaxException {

        URIBuilder redirectUri =
                new URIBuilder(credentialIssuerConfig.getAuthorizeUrl())
                        .addParameter("client_id", credentialIssuerConfig.getClientId())
                        .addParameter("request", jweObject.serialize());

        if (credentialIssuerConfig.getId().equals(DCMAW_CRI_ID)
                || credentialIssuerConfig.getId().equals(STUB_DCMAW_CRI_ID)) {
            redirectUri.addParameter("response_type", "code");
        }

        return new CriResponse(
                new CriDetails(credentialIssuerConfig.getId(), redirectUri.build().toString()));
    }

    private JWEObject signEncryptJar(
            CredentialIssuerConfig credentialIssuerConfig,
            String userId,
            String oauthState,
            String govukSigninJourneyId,
            List<VcStatusDto> currentVcStatuses,
            String criId)
            throws HttpResponseExceptionWithErrorBody, ParseException, JOSEException {
        SharedClaimsResponse sharedClaimsResponse =
                getSharedAttributes(userId, currentVcStatuses, criId);
        SignedJWT signedJWT =
                AuthorizationRequestHelper.createSignedJWT(
                        sharedClaimsResponse,
                        signer,
                        credentialIssuerConfig,
                        credentialIssuerConfigService,
                        oauthState,
                        userId,
                        govukSigninJourneyId);

        RSAEncrypter rsaEncrypter = new RSAEncrypter(credentialIssuerConfig.getEncryptionKey());
        return AuthorizationRequestHelper.createJweObject(rsaEncrypter, signedJWT);
    }

    @Tracing
    private Optional<ErrorResponse> validate(Map<String, String> pathParameters) {
        if (pathParameters == null || StringUtils.isBlank(pathParameters.get(CRI_ID))) {
            return Optional.of(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
        }
        LogHelper.attachCriIdToLogs(pathParameters.get(CRI_ID));
        return Optional.empty();
    }

    @Tracing
    private CredentialIssuerConfig getCredentialIssuerConfig(String criId) {
        return credentialIssuerConfigService.getCredentialIssuerActiveConnectionConfig(criId);
    }

    @Tracing
    private SharedClaimsResponse getSharedAttributes(
            String userId, List<VcStatusDto> currentVcStatuses, String criId)
            throws HttpResponseExceptionWithErrorBody {
        String addressCriId =
                credentialIssuerConfigService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID);
        CredentialIssuerConfig addressCriConfig =
                credentialIssuerConfigService.getCredentialIssuerActiveConnectionConfig(
                        addressCriId);

        List<String> credentials = userIdentityService.getUserIssuedCredentials(userId);

        Set<SharedClaims> sharedClaimsSet = new HashSet<>();
        List<String> criAllowedSharedClaimAttrs = getAllowedSharedClaimAttrs(criId);
        boolean hasAddressVc = false;
        for (String credential : credentials) {
            try {
                SignedJWT signedJWT = SignedJWT.parse(credential);
                String credentialIss = signedJWT.getJWTClaimsSet().getIssuer();

                VcStatusDto vcStatus =
                        currentVcStatuses.stream()
                                .filter(
                                        vcStatusDto ->
                                                vcStatusDto.getCriIss().equals(credentialIss))
                                .findFirst()
                                .orElseThrow();

                if (vcStatus.getIsSuccessfulVc().equals(Boolean.TRUE)) {
                    JsonNode credentialSubject =
                            mapper.readTree(signedJWT.getPayload().toString())
                                    .path(VC_CLAIM)
                                    .path(VC_CREDENTIAL_SUBJECT);
                    if (credentialSubject.isMissingNode()) {
                        LOGGER.error("Credential subject missing from verified credential");
                        throw new HttpResponseExceptionWithErrorBody(
                                500, ErrorResponse.CREDENTIAL_SUBJECT_MISSING);
                    }

                    SharedClaims credentialsSharedClaims =
                            mapper.readValue(credentialSubject.toString(), SharedClaims.class);
                    if (credentialIss.equals(addressCriConfig.getComponentId())) {
                        hasAddressVc = true;
                        sharedClaimsSet.forEach(sharedClaims -> sharedClaims.setAddress(null));
                    } else if (hasAddressVc) {
                        credentialsSharedClaims.setAddress(null);
                    }
                    verifyForAllowedSharedClaimAttrs(
                            credentialsSharedClaims, criAllowedSharedClaimAttrs);
                    sharedClaimsSet.add(credentialsSharedClaims);
                }
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
        return SharedClaimsResponse.from(sharedClaimsSet);
    }

    private void verifyForAllowedSharedClaimAttrs(
            SharedClaims credentialsSharedClaims, List<String> allowedSharedAttr) {
        if (!allowedSharedAttr.contains(SHARED_CLAIM_ATTR_NAME)) {
            credentialsSharedClaims.setName(null);
        }
        if (!allowedSharedAttr.contains(SHARED_CLAIM_ATTR_BIRTH_DATE)) {
            credentialsSharedClaims.setBirthDate(null);
        }
        if (!allowedSharedAttr.contains(SHARED_CLAIM_ATTR_ADDRESS)) {
            credentialsSharedClaims.setAddress(null);
        }
    }

    private List<String> getAllowedSharedClaimAttrs(String criId) {
        String allowedSharedAttributes =
                credentialIssuerConfigService.getAllowedSharedAttributes(criId);
        return allowedSharedAttributes == null
                ? Arrays.asList(DEFAULT_ALLOWED_SHARED_ATTR.split(REGEX_COMMA_SEPARATION))
                : Arrays.asList(allowedSharedAttributes.split(REGEX_COMMA_SEPARATION));
    }

    @Tracing
    private void persistOauthState(IpvSessionItem ipvSessionItem, String criId, String oauthState) {
        ipvSessionItem.setCriOAuthSessionId(oauthState);
        ipvSessionService.updateIpvSession(ipvSessionItem);
    }

    @Tracing
    private void persistCriOauthState(String oauthState, String criId) {
        criOAuthSessionService.persistCriOAuthSession(oauthState, criId);
    }
}
