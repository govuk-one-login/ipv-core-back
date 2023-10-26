package uk.gov.di.ipv.core.buildcrioauthrequest;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
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
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.EvidenceRequest;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.SharedClaims;
import uk.gov.di.ipv.core.library.domain.SharedClaimsResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.kmses256signer.KmsEs256Signer;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;

import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_REDIRECT_URI;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getFeatureSet;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getJourney;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;

public class BuildCriOauthRequestHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String DCMAW_CRI_ID = "dcmaw";
    public static final String SHARED_CLAIM_ATTR_NAME = "name";
    public static final String SHARED_CLAIM_ATTR_BIRTH_DATE = "birthDate";
    public static final String SHARED_CLAIM_ATTR_ADDRESS = "address";
    public static final String SHARED_CLAIM_ATTR_EMAIL = "emailAddress";
    public static final String SHARED_CLAIM_ATTR_SOCIAL_SECURITY_RECORD = "socialSecurityRecord";
    public static final String DEFAULT_ALLOWED_SHARED_ATTR = "name,birthDate,address";
    public static final String REGEX_COMMA_SEPARATION = "\\s*,\\s*";
    public static final Pattern LAST_SEGMENT_PATTERN = Pattern.compile("/([^/]+)$");

    private final ObjectMapper mapper = new ObjectMapper();
    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final JWSSigner signer;
    private final AuditService auditService;
    private final IpvSessionService ipvSessionService;
    private final CriOAuthSessionService criOAuthSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;

    public BuildCriOauthRequestHandler(
            ConfigService configService,
            UserIdentityService userIdentityService,
            JWSSigner signer,
            AuditService auditService,
            IpvSessionService ipvSessionService,
            CriOAuthSessionService criOAuthSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator) {

        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.signer = signer;
        this.auditService = auditService;
        this.ipvSessionService = ipvSessionService;
        this.criOAuthSessionService = criOAuthSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        VcHelper.setConfigService(this.configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public BuildCriOauthRequestHandler() {
        this.configService = new ConfigService();
        this.userIdentityService = new UserIdentityService(configService);
        this.signer = new KmsEs256Signer();
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.criOAuthSessionService = new CriOAuthSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator(configService, ipvSessionService);
        VcHelper.setConfigService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest input, Context context) {
        LogHelper.attachComponentIdToLogs(configService);
        if (signer instanceof KmsEs256Signer kmsEs256Signer) {
            kmsEs256Signer.setKeyId(configService.getSigningKeyId());
        }
        try {
            String ipvSessionId = getIpvSessionId(input);
            String ipAddress = getIpAddress(input);
            String featureSet = getFeatureSet(input);
            configService.setFeatureSet(featureSet);
            String journey = getJourney(input);

            var errorResponse = validate(journey);
            if (errorResponse.isPresent()) {
                return new JourneyErrorResponse(
                                JOURNEY_ERROR_PATH, HttpStatus.SC_BAD_REQUEST, errorResponse.get())
                        .toObjectMap();
            }

            String criId = getCriIdFromJourney(journey);
            String connection = configService.getActiveConnection(criId);
            CredentialIssuerConfig criConfig =
                    configService.getCriConfigForConnection(connection, criId);

            if (criConfig == null) {
                return new JourneyErrorResponse(
                                JOURNEY_ERROR_PATH,
                                HttpStatus.SC_BAD_REQUEST,
                                ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID)
                        .toObjectMap();
            }

            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            String clientOAuthSessionId = ipvSessionItem.getClientOAuthSessionId();
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(clientOAuthSessionId);

            String userId = clientOAuthSessionItem.getUserId();

            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();

            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            String oauthState = SecureTokenHelper.generate();
            JWEObject jweObject =
                    signEncryptJar(
                            ipvSessionItem,
                            criConfig,
                            userId,
                            oauthState,
                            govukSigninJourneyId,
                            criId);

            CriResponse criResponse = getCriResponse(criConfig, jweObject, criId);

            persistOauthState(ipvSessionItem, oauthState);

            persistCriOauthState(oauthState, criId, clientOAuthSessionId, connection);

            AuditEventUser auditEventUser =
                    new AuditEventUser(userId, ipvSessionId, govukSigninJourneyId, ipAddress);
            auditService.sendAuditEvent(
                    new AuditEvent(
                            AuditEventTypes.IPV_REDIRECT_TO_CRI,
                            configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser));

            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_LAMBDA_RESULT.getFieldName(),
                                    "Successfully generated ipv cri oauth request.")
                            .with(
                                    LOG_REDIRECT_URI.getFieldName(),
                                    criResponse.getCri().getRedirectUrl());
            LOGGER.info(message);

            return criResponse.toObjectMap();

        } catch (HttpResponseExceptionWithErrorBody e) {
            if (ErrorResponse.MISSING_IPV_SESSION_ID.equals(e.getErrorResponse())) {
                return new JourneyErrorResponse(
                                JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                        .toObjectMap();
            }
            LogHelper.logErrorMessage("Failed to create cri JAR", e.getErrorReason());
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            e.getErrorResponse())
                    .toObjectMap();
        } catch (SqsException e) {
            LogHelper.logErrorMessage("Failed to send audit event to SQS queue.", e.getMessage());
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT,
                            e.getMessage())
                    .toObjectMap();
        } catch (ParseException | JOSEException e) {
            LogHelper.logErrorMessage("Failed to parse encryption public JWK.", e.getMessage());
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_BAD_REQUEST,
                            ErrorResponse.FAILED_TO_PARSE_CREDENTIAL_ISSUER_CONFIG)
                    .toObjectMap();
        } catch (URISyntaxException e) {
            LogHelper.logErrorMessage("Failed to construct redirect uri.", e.getMessage());
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_CONSTRUCT_REDIRECT_URI,
                            e.getMessage())
                    .toObjectMap();
        } catch (UnknownEvidenceTypeException e) {
            LOGGER.error("Unable to determine type of credential.", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE,
                            e.getMessage())
                    .toObjectMap();
        }
    }

    private String getCriIdFromJourney(String journey) {
        Matcher matcher = LAST_SEGMENT_PATTERN.matcher(journey);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return journey;
    }

    private CriResponse getCriResponse(
            CredentialIssuerConfig credentialIssuerConfig, JWEObject jweObject, String criId)
            throws URISyntaxException {

        URIBuilder redirectUri =
                new URIBuilder(credentialIssuerConfig.getAuthorizeUrl())
                        .addParameter("client_id", credentialIssuerConfig.getClientId())
                        .addParameter("request", jweObject.serialize());

        if (criId.equals(DCMAW_CRI_ID)) {
            redirectUri.addParameter("response_type", "code");
        }

        return new CriResponse(new CriDetails(criId, redirectUri.build().toString()));
    }

    private JWEObject signEncryptJar(
            IpvSessionItem ipvSessionItem,
            CredentialIssuerConfig credentialIssuerConfig,
            String userId,
            String oauthState,
            String govukSigninJourneyId,
            String criId)
            throws HttpResponseExceptionWithErrorBody, ParseException, JOSEException,
                    UnknownEvidenceTypeException {

        List<SignedJWT> credentials = getSignedJWTs(userId);

        SharedClaimsResponse sharedClaimsResponse =
                getSharedAttributesForUser(ipvSessionItem, credentials, criId);
        EvidenceRequest evidenceRequest = null;

        if (criId.equals(F2F_CRI)) {
            evidenceRequest = getEvidenceRequestForF2F(credentials);
        }
        SignedJWT signedJWT =
                AuthorizationRequestHelper.createSignedJWT(
                        sharedClaimsResponse,
                        signer,
                        credentialIssuerConfig,
                        configService,
                        oauthState,
                        userId,
                        govukSigninJourneyId,
                        evidenceRequest);

        RSAEncrypter rsaEncrypter = new RSAEncrypter(credentialIssuerConfig.getEncryptionKey());
        return AuthorizationRequestHelper.createJweObject(rsaEncrypter, signedJWT);
    }

    private EvidenceRequest getEvidenceRequestForF2F(List<SignedJWT> credentials)
            throws UnknownEvidenceTypeException, ParseException {
        Gpg45Scores gpg45Scores = gpg45ProfileEvaluator.buildScore(credentials);
        List<Gpg45Scores> requiredEvidences =
                gpg45Scores.calculateGpg45ScoresRequiredToMeetAProfile(
                        Gpg45ProfileEvaluator.CURRENT_ACCEPTED_GPG45_PROFILES);

        OptionalInt minViableStrengthOpt =
                requiredEvidences.stream()
                        .filter(
                                requiredScores ->
                                        requiredScores.getEvidences().size() == 1
                                                & requiredScores.getActivity() == 0
                                                & requiredScores.getFraud() == 0
                                                & requiredScores.getVerification() == 0)
                        .map(subList -> subList.getEvidences().get(0))
                        .mapToInt(Gpg45Scores.Evidence::getStrength)
                        .min();

        if (minViableStrengthOpt.isEmpty()) {
            LOGGER.error("Minimum strength evidence required cannot be attained.");
            return null;
        }

        return new EvidenceRequest(minViableStrengthOpt.getAsInt());
    }

    private List<SignedJWT> getSignedJWTs(String userId) throws HttpResponseExceptionWithErrorBody {
        List<String> credentials = userIdentityService.getUserIssuedCredentials(userId);
        List<SignedJWT> signedJWTs = new ArrayList<>();

        for (String credential : credentials) {
            try {
                signedJWTs.add(SignedJWT.parse(credential));
            } catch (ParseException e) {
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
            }
        }
        return signedJWTs;
    }

    @Tracing
    private Optional<ErrorResponse> validate(String journey) {
        if (StringUtils.isBlank(journey)) {
            return Optional.of(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
        }
        LogHelper.attachCriIdToLogs(journey);
        return Optional.empty();
    }

    @Tracing
    private SharedClaimsResponse getSharedAttributesForUser(
            IpvSessionItem ipvSessionItem, List<SignedJWT> credentials, String criId)
            throws HttpResponseExceptionWithErrorBody {

        Set<SharedClaims> sharedClaimsSet = new HashSet<>();
        List<String> criAllowedSharedClaimAttrs = getAllowedSharedClaimAttrs(criId);
        boolean hasAddressVc = false;
        for (SignedJWT credential : credentials) {
            try {
                String credentialIss = credential.getJWTClaimsSet().getIssuer();

                if (VcHelper.isSuccessfulVcIgnoringCi(credential)) {
                    JsonNode credentialSubject =
                            mapper.readTree(credential.getPayload().toString())
                                    .path(VC_CLAIM)
                                    .path(VC_CREDENTIAL_SUBJECT);
                    if (credentialSubject.isMissingNode()) {
                        LOGGER.error("Credential subject missing from verified credential");
                        throw new HttpResponseExceptionWithErrorBody(
                                500, ErrorResponse.CREDENTIAL_SUBJECT_MISSING);
                    }

                    SharedClaims credentialsSharedClaims =
                            mapper.readValue(credentialSubject.toString(), SharedClaims.class);
                    if (credentialIss.equals(configService.getComponentId(ADDRESS_CRI))) {
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
                LogHelper.logErrorMessage("Failed to get Shared Attributes.", e.getMessage());
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.FAILED_TO_GET_SHARED_ATTRIBUTES);
            } catch (ParseException e) {
                LogHelper.logErrorMessage("Failed to parse issued credentials.", e.getMessage());
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
            }
        }
        return SharedClaimsResponse.from(
                sharedClaimsSet,
                getEmailAddressFromIpvSession(ipvSessionItem, criAllowedSharedClaimAttrs));
    }

    private String getEmailAddressFromIpvSession(
            IpvSessionItem ipvSessionItem, List<String> allowedSharedAttr) {
        if (ipvSessionItem.getEmailAddress() != null
                && allowedSharedAttr.contains(SHARED_CLAIM_ATTR_EMAIL)) {
            return ipvSessionItem.getEmailAddress();
        }
        return null;
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
        if (!allowedSharedAttr.contains(SHARED_CLAIM_ATTR_SOCIAL_SECURITY_RECORD)) {
            credentialsSharedClaims.setSocialSecurityRecord(null);
        }
    }

    private List<String> getAllowedSharedClaimAttrs(String criId) {
        String allowedSharedAttributes = configService.getAllowedSharedAttributes(criId);
        return allowedSharedAttributes == null
                ? Arrays.asList(DEFAULT_ALLOWED_SHARED_ATTR.split(REGEX_COMMA_SEPARATION))
                : Arrays.asList(allowedSharedAttributes.split(REGEX_COMMA_SEPARATION));
    }

    @Tracing
    private void persistOauthState(IpvSessionItem ipvSessionItem, String oauthState) {
        ipvSessionItem.setCriOAuthSessionId(oauthState);
        ipvSessionService.updateIpvSession(ipvSessionItem);
    }

    @Tracing
    private void persistCriOauthState(
            String oauthState, String criId, String clientOAuthSessionId, String connection) {
        criOAuthSessionService.persistCriOAuthSession(
                oauthState, criId, clientOAuthSessionId, connection);
    }
}
