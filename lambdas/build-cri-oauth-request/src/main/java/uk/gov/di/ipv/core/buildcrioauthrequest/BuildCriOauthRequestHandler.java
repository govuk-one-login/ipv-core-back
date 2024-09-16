package uk.gov.di.ipv.core.buildcrioauthrequest;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.buildcrioauthrequest.domain.CriDetails;
import uk.gov.di.ipv.core.buildcrioauthrequest.domain.CriResponse;
import uk.gov.di.ipv.core.buildcrioauthrequest.domain.SharedClaims;
import uk.gov.di.ipv.core.buildcrioauthrequest.helpers.AuthorizationRequestHelper;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.CriJourneyRequest;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.EvidenceRequest;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.kmses256signer.SignerFactory;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.model.AddressAssertion;
import uk.gov.di.model.IdentityCheckSubject;
import uk.gov.di.model.PersonWithDocuments;
import uk.gov.di.model.PersonWithIdentity;

import java.net.URISyntaxException;
import java.security.InvalidParameterException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.apache.http.HttpStatus.SC_BAD_REQUEST;
import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.Cri.DWP_KBV;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_CONSTRUCT_REDIRECT_URI;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_EVIDENCE_REQUESTED;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.domain.EvidenceRequest.SCORING_POLICY_GPG45;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_REDIRECT_URI;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getFeatureSet;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getJourneyParameter;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getLanguage;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;

public class BuildCriOauthRequestHandler
        implements RequestHandler<CriJourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    public static final String SHARED_CLAIM_ATTR_NAME = "name";
    public static final String SHARED_CLAIM_ATTR_BIRTH_DATE = "birthDate";
    public static final String SHARED_CLAIM_ATTR_ADDRESS = "address";
    public static final String SHARED_CLAIM_ATTR_EMAIL = "emailAddress";
    public static final String SHARED_CLAIM_ATTR_SOCIAL_SECURITY_RECORD = "socialSecurityRecord";
    public static final String DEFAULT_ALLOWED_SHARED_ATTR = "name,birthDate,address";
    public static final String REGEX_COMMA_SEPARATION = "\\s*,\\s*";
    public static final Pattern LAST_SEGMENT_PATTERN = Pattern.compile("/([^/]+)$");
    public static final String CONTEXT = "context";
    public static final String EVIDENCE_REQUESTED = "evidenceRequest";

    private final ConfigService configService;
    private final SignerFactory signerFactory;
    private final AuditService auditService;
    private final IpvSessionService ipvSessionService;
    private final CriOAuthSessionService criOAuthSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final SessionCredentialsService sessionCredentialsService;

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public BuildCriOauthRequestHandler(
            ConfigService configService,
            SignerFactory signerFactory,
            AuditService auditService,
            IpvSessionService ipvSessionService,
            CriOAuthSessionService criOAuthSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            SessionCredentialsService sessionCredentialsService) {
        this.configService = configService;
        this.signerFactory = signerFactory;
        this.auditService = auditService;
        this.ipvSessionService = ipvSessionService;
        this.criOAuthSessionService = criOAuthSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.sessionCredentialsService = sessionCredentialsService;
        VcHelper.setConfigService(this.configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public BuildCriOauthRequestHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public BuildCriOauthRequestHandler(ConfigService configService) {
        this.configService = configService;
        this.signerFactory = new SignerFactory(configService);
        this.auditService = AuditService.create(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.criOAuthSessionService = new CriOAuthSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        VcHelper.setConfigService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(CriJourneyRequest input, Context context) {
        LogHelper.attachComponentId(configService);
        try {
            String ipvSessionId = getIpvSessionId(input);
            String ipAddress = getIpAddress(input);
            String language = getLanguage(input);
            configService.setFeatureSet(getFeatureSet(input));

            var cri = getCriFromJourney(input.getJourneyUri().getPath());
            if (cri == null) {
                return new JourneyErrorResponse(
                                JOURNEY_ERROR_PATH,
                                SC_BAD_REQUEST,
                                ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID)
                        .toObjectMap();
            }
            LogHelper.attachCriIdToLogs(cri);

            String criContext = getJourneyParameter(input, CONTEXT);
            EvidenceRequest criEvidenceRequest =
                    EvidenceRequest.fromBase64(getJourneyParameter(input, EVIDENCE_REQUESTED));
            String connection = configService.getActiveConnection(cri);
            OauthCriConfig criConfig =
                    configService.getOauthCriConfigForConnection(connection, cri);

            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            String clientOAuthSessionId = ipvSessionItem.getClientOAuthSessionId();
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(clientOAuthSessionId);

            String userId = clientOAuthSessionItem.getUserId();

            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();

            Vot targetVot = ipvSessionItem.getTargetVot();

            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            String oauthState = SecureTokenHelper.getInstance().generate();
            JWEObject jweObject =
                    signEncryptJar(
                            ipvSessionItem,
                            criConfig,
                            userId,
                            oauthState,
                            govukSigninJourneyId,
                            cri,
                            criContext,
                            criEvidenceRequest,
                            targetVot);

            CriResponse criResponse = getCriResponse(criConfig, jweObject, cri, language);

            persistOauthState(ipvSessionItem, oauthState);

            persistCriOauthState(oauthState, cri, clientOAuthSessionId, connection);

            AuditEventUser auditEventUser =
                    new AuditEventUser(userId, ipvSessionId, govukSigninJourneyId, ipAddress);
            auditService.sendAuditEvent(
                    AuditEvent.createWithDeviceInformation(
                            AuditEventTypes.IPV_REDIRECT_TO_CRI,
                            configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser,
                            new AuditRestrictedDeviceInformation(input.getDeviceInformation())));

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

        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            return buildJourneyErrorResponse(
                    e.getErrorReason(), e, e.getResponseCode(), e.getErrorResponse());
        } catch (ParseException | JOSEException e) {
            return buildJourneyErrorResponse(
                    "Failed to parse encryption public JWK",
                    e,
                    SC_BAD_REQUEST,
                    FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        } catch (URISyntaxException e) {
            return buildJourneyErrorResponse(
                    "Failed to construct redirect uri",
                    e,
                    SC_INTERNAL_SERVER_ERROR,
                    FAILED_TO_CONSTRUCT_REDIRECT_URI);
        } catch (JsonProcessingException e) {
            return buildJourneyErrorResponse(
                    "Failed to parse evidenceRequest.",
                    e,
                    SC_INTERNAL_SERVER_ERROR,
                    FAILED_TO_PARSE_EVIDENCE_REQUESTED);
        } catch (IllegalArgumentException e) {
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            SC_BAD_REQUEST,
                            ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID)
                    .toObjectMap();
        } catch (IpvSessionNotFoundException e) {
            return buildJourneyErrorResponse(
                    "Failed to find ipv session.",
                    e,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    IPV_SESSION_NOT_FOUND);
        } finally {
            auditService.awaitAuditEvents();
        }
    }

    private Map<String, Object> buildJourneyErrorResponse(
            String errorMessage, Exception e, int statusCode, ErrorResponse errorResponse) {
        LOGGER.error(LogHelper.buildErrorMessage(errorMessage, e));
        return new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH, statusCode, errorResponse, e.getMessage())
                .toObjectMap();
    }

    private Cri getCriFromJourney(String journeyPath) {
        Matcher matcher = LAST_SEGMENT_PATTERN.matcher(journeyPath);
        if (matcher.find()) {
            try {
                return Cri.fromId(matcher.group(1));
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        return null;
    }

    private CriResponse getCriResponse(
            OauthCriConfig oauthCriConfig, JWEObject jweObject, Cri cri, String language)
            throws URISyntaxException {

        URIBuilder redirectUri =
                new URIBuilder(oauthCriConfig.getAuthorizeUrl())
                        .addParameter("client_id", oauthCriConfig.getClientId())
                        .addParameter("request", jweObject.serialize());

        if (cri.equals(DCMAW)) {
            redirectUri.addParameter("response_type", "code");
        }

        if (cri.equals(DWP_KBV)) {
            redirectUri.addParameter("lng", language);
        }

        return new CriResponse(new CriDetails(cri.getId(), redirectUri.build().toString()));
    }

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    private JWEObject signEncryptJar(
            IpvSessionItem ipvSessionItem,
            OauthCriConfig oauthCriConfig,
            String userId,
            String oauthState,
            String govukSigninJourneyId,
            Cri cri,
            String context,
            EvidenceRequest evidenceRequest,
            Vot requestedVot)
            throws HttpResponseExceptionWithErrorBody, ParseException, JOSEException,
                    VerifiableCredentialException {

        var vcs =
                sessionCredentialsService.getCredentials(ipvSessionItem.getIpvSessionId(), userId);

        var sharedClaims = getSharedAttributesForUser(ipvSessionItem, vcs, cri);

        if (cri.equals(F2F)) {
            evidenceRequest = getEvidenceRequestForF2F(vcs, requestedVot);
        } else if (cri.isKbvCri()) {
            evidenceRequest = getEvidenceRequestForKbvCri(ipvSessionItem.getTargetVot());
        }
        SignedJWT signedJWT =
                AuthorizationRequestHelper.createSignedJWT(
                        sharedClaims,
                        signerFactory.getSigner(),
                        oauthCriConfig,
                        configService,
                        oauthState,
                        userId,
                        govukSigninJourneyId,
                        evidenceRequest,
                        context);

        RSAEncrypter rsaEncrypter = new RSAEncrypter(oauthCriConfig.getParsedEncryptionKey());
        return AuthorizationRequestHelper.createJweObject(rsaEncrypter, signedJWT);
    }

    private EvidenceRequest getEvidenceRequestForF2F(
            List<VerifiableCredential> vcs, Vot requestedVot) {
        var gpg45Scores = gpg45ProfileEvaluator.buildScore(vcs);
        List<Gpg45Scores> requiredEvidences =
                gpg45Scores.calculateGpg45ScoresRequiredToMeetAProfile(
                        requestedVot.getSupportedGpg45Profiles());

        OptionalInt minViableStrengthOpt =
                requiredEvidences.stream()
                        .filter(
                                requiredScores ->
                                        requiredScores.getEvidences().size() <= 1
                                                && requiredScores.getActivity() == 0
                                                && requiredScores.getFraud() == 0
                                                && requiredScores.getVerification() <= 3)
                        .mapToInt(
                                requiredScores ->
                                        requiredScores.getEvidences().isEmpty()
                                                ? 0
                                                : requiredScores
                                                        .getEvidences()
                                                        .get(0)
                                                        .getStrength())
                        .min();

        if (minViableStrengthOpt.isEmpty()) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                            "Minimum strength evidence required cannot be attained."));
            return null;
        }

        return new EvidenceRequest(SCORING_POLICY_GPG45, minViableStrengthOpt.getAsInt(), null);
    }

    private EvidenceRequest getEvidenceRequestForKbvCri(Vot targetVot) {
        var verificationScoreRequired =
                switch (targetVot) {
                    case P1 -> 1;
                    case P2 -> 2;
                    default -> throw new InvalidParameterException(
                            "Cannot calculate verification score required for vot: " + targetVot);
                };

        return new EvidenceRequest(SCORING_POLICY_GPG45, null, verificationScoreRequired);
    }

    private SharedClaims getSharedAttributesForUser(
            IpvSessionItem ipvSessionItem, List<VerifiableCredential> vcs, Cri cri) {
        var sharedClaims = new SharedClaims();
        var criAllowedSharedClaimAttrs = getAllowedSharedClaimAttrs(cri);

        // Email address is provided separately in the session, not from a VC
        sharedClaims.setEmailAddress(ipvSessionItem.getEmailAddress());

        // Other shared claims are added from successful VCs
        for (var vc : vcs) {
            if (VcHelper.isSuccessfulVc(vc)) {
                var credentialSubject = vc.getCredential().getCredentialSubject();

                if (credentialSubject instanceof PersonWithIdentity personWithIdentity
                        && personWithIdentity.getName() != null) {
                    sharedClaims.getName().addAll(personWithIdentity.getName());
                }
                if (credentialSubject instanceof PersonWithIdentity personWithIdentity
                        && personWithIdentity.getBirthDate() != null) {
                    sharedClaims.getBirthDate().addAll(personWithIdentity.getBirthDate());
                }
                if (ADDRESS.equals(vc.getCri())
                        && credentialSubject instanceof AddressAssertion addressAssertion
                        && addressAssertion.getAddress() != null) {
                    sharedClaims.getAddress().addAll(addressAssertion.getAddress());
                }
                // TODO: should update tests to avoid needing this
                if (ADDRESS.equals(vc.getCri())
                        && credentialSubject instanceof IdentityCheckSubject addressAssertion) {
                    sharedClaims.setAddress(
                            addressAssertion.getAddress().stream().collect(Collectors.toSet()));
                }
                if (credentialSubject instanceof PersonWithDocuments personWithDocuments
                        && personWithDocuments.getSocialSecurityRecord() != null) {
                    sharedClaims
                            .getSocialSecurityRecord()
                            .addAll(personWithDocuments.getSocialSecurityRecord());
                }
            }
        }

        LOGGER.info(
                LogHelper.buildLogMessage("Found shared claims")
                        .with("names", sharedClaims.getName().size())
                        .with("birthDates", sharedClaims.getBirthDate().size())
                        .with("addresses", sharedClaims.getAddress().size())
                        .with("emails", sharedClaims.getEmailAddress() == null ? 0 : 1)
                        .with(
                                "socialSecurityRecords",
                                sharedClaims.getSocialSecurityRecord().size()));

        stripDisallowedSharedClaims(sharedClaims, criAllowedSharedClaimAttrs);

        return sharedClaims;
    }

    private void stripDisallowedSharedClaims(
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
        if (!allowedSharedAttr.contains(SHARED_CLAIM_ATTR_EMAIL)) {
            credentialsSharedClaims.setEmailAddress(null);
        }
        if (!allowedSharedAttr.contains(SHARED_CLAIM_ATTR_SOCIAL_SECURITY_RECORD)) {
            credentialsSharedClaims.setSocialSecurityRecord(null);
        }
    }

    private List<String> getAllowedSharedClaimAttrs(Cri cri) {
        String allowedSharedAttributes =
                configService.getParameter(
                        ConfigurationVariable.CREDENTIAL_ISSUER_SHARED_ATTRIBUTES, cri.getId());
        return allowedSharedAttributes == null
                ? Arrays.asList(DEFAULT_ALLOWED_SHARED_ATTR.split(REGEX_COMMA_SEPARATION))
                : Arrays.asList(allowedSharedAttributes.split(REGEX_COMMA_SEPARATION));
    }

    private void persistOauthState(IpvSessionItem ipvSessionItem, String oauthState) {
        ipvSessionItem.setCriOAuthSessionId(oauthState);
        ipvSessionService.updateIpvSession(ipvSessionItem);
    }

    private void persistCriOauthState(
            String oauthState, Cri cri, String clientOAuthSessionId, String connection) {
        criOAuthSessionService.persistCriOAuthSession(
                oauthState, cri, clientOAuthSessionId, connection);
    }
}
