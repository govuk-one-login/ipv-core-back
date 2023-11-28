package uk.gov.di.ipv.core.checkexistingidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionGpg45ProfileMatched;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.StringJoiner;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.RESET_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_TXN;
import static uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator.CURRENT_ACCEPTED_GPG45_PROFILES;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_CODE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_JOURNEY_RESPONSE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_PROFILE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_UNCORRELATABLE_DATA;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NEXT_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_PENDING_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_RESET_IDENTITY_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REUSE_PATH;

/** Check Existing Identity response Lambda */
public class CheckExistingIdentityHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final int ONLY = 0;
    private static final Logger LOGGER = LogManager.getLogger();

    private static final Map<String, Object> JOURNEY_REUSE =
            new JourneyResponse(JOURNEY_REUSE_PATH).toObjectMap();
    private static final Map<String, Object> JOURNEY_PENDING =
            new JourneyResponse(JOURNEY_PENDING_PATH).toObjectMap();
    private static final Map<String, Object> JOURNEY_NEXT =
            new JourneyResponse(JOURNEY_NEXT_PATH).toObjectMap();
    private static final Map<String, Object> JOURNEY_F2F_FAIL =
            new JourneyResponse(JOURNEY_F2F_FAIL_PATH).toObjectMap();
    private static final Map<String, Object> JOURNEY_RESET_IDENTITY =
            new JourneyResponse(JOURNEY_RESET_IDENTITY_PATH).toObjectMap();
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH);
    public static final String NAMES = "names";
    public static final String DATE_OF_BIRTH = "dob";
    public static final String VOT_P2 = "P2";

    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final CriResponseService criResponseService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final AuditService auditService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CiMitService ciMitService;

    @SuppressWarnings("unused") // Used by AWS
    public CheckExistingIdentityHandler(
            ConfigService configService,
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            AuditService auditService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService,
            CiMitService ciMitService) {
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.auditService = auditService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
        this.ciMitService = ciMitService;
        VcHelper.setConfigService(this.configService);
    }

    @SuppressWarnings("unused") // Used through dependency injection
    @ExcludeFromGeneratedCoverageReport
    public CheckExistingIdentityHandler() {
        this.configService = new ConfigService();
        this.userIdentityService = new UserIdentityService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator(configService, ipvSessionService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.criResponseService = new CriResponseService(configService);
        this.ciMitService = new CiMitService(configService);
        VcHelper.setConfigService(this.configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest event, Context context) {
        LogHelper.attachComponentIdToLogs(configService);

        try {
            String ipvSessionId = getIpvSessionId(event);
            String ipAddress = getIpAddress(event);
            String featureSet = RequestHelper.getFeatureSet(event);
            configService.setFeatureSet(featureSet);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            String userId = clientOAuthSessionItem.getUserId();

            // Reset identity if reprove is true.
            Boolean reproveIdentity = clientOAuthSessionItem.getReproveIdentity();
            if (!Objects.isNull(reproveIdentity) && reproveIdentity) {
                return buildForceResetResponse();
            }

            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            AuditEventUser auditEventUser =
                    new AuditEventUser(userId, ipvSessionId, govukSigninJourneyId, ipAddress);

            CriResponseItem f2fRequest = criResponseService.getFaceToFaceRequest(userId);
            VcStoreItem f2fVc = userIdentityService.getVcStoreItem(userId, F2F_CRI);

            final boolean isF2FIncomplete = !Objects.isNull(f2fRequest) && Objects.isNull(f2fVc);
            final boolean isF2FComplete = !Objects.isNull(f2fRequest) && !Objects.isNull(f2fVc);

            // Incomplete F2F journey
            if (isF2FIncomplete) {
                return buildF2FIncompleteResponse(f2fRequest);
            }

            var contraIndicators =
                    ciMitService.getContraIndicatorsVC(
                            clientOAuthSessionItem.getUserId(), govukSigninJourneyId, ipAddress);

            // CI scoring failure
            if (userIdentityService.breachingCiThreshold(contraIndicators)) {
                ipvSessionItem.setCiFail(false);
                ipvSessionService.updateIpvSession(ipvSessionItem);

                return buildCiBreachingResponse(contraIndicators);
            }

            List<SignedJWT> credentials =
                    gpg45ProfileEvaluator.parseCredentials(
                            userIdentityService.getUserIssuedCredentials(userId));

            // Credential correlation failure
            if (!vcDataCorrelates(userId)) {
                return isF2FComplete
                        ? buildF2FNotCorrelatedResponse(auditEventUser)
                        : buildNotCorrelatedResponse(auditEventUser);
            }

            // Force reset
            if (configService.enabled(RESET_IDENTITY.getName())) {
                return buildForceResetResponse();
            }

            Gpg45Scores gpg45Scores = gpg45ProfileEvaluator.buildScore(credentials);
            Optional<Gpg45Profile> matchedProfile =
                    gpg45ProfileEvaluator.getFirstMatchingProfile(
                            gpg45Scores, CURRENT_ACCEPTED_GPG45_PROFILES);

            // No profile match
            if (matchedProfile.isEmpty()) {
                return isF2FComplete
                        ? buildF2FNoMatchResponse(auditEventUser)
                        : buildNoMatchResponse(credentials, auditEventUser);
            }

            // Successful match
            sendProfileMatchedAuditEvent(
                    matchedProfile.get(), gpg45Scores, credentials, auditEventUser);

            ipvSessionItem.setVot(VOT_P2);
            ipvSessionService.updateIpvSession(ipvSessionItem);

            return buildProfileMatchedResponse(matchedProfile.get(), auditEventUser);
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error(e.getErrorResponse().getMessage(), e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (CiRetrievalException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_GET_STORED_CIS, e);
        } catch (ParseException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS, e);
        } catch (UnknownEvidenceTypeException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE, e);
        } catch (SqsException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT, e);
        } catch (CredentialParseException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS, e);
        } catch (ConfigException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_PARSE_CONFIG, e);
        } catch (UnrecognisedCiException e) {
            return buildErrorResponse(ErrorResponse.UNRECOGNISED_CI_CODE, e);
        }
    }

    @Tracing
    private Map<String, Object> buildF2FIncompleteResponse(CriResponseItem faceToFaceRequest) {
        switch (faceToFaceRequest.getStatus()) {
            case CriResponseService.STATUS_PENDING -> {
                LOGGER.info(
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "F2F cri pending verification."));
                return JOURNEY_PENDING;
            }
            case CriResponseService.STATUS_ERROR -> {
                LOGGER.info(
                        new StringMapMessage()
                                .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "F2F cri error"));
                return JOURNEY_F2F_FAIL;
            }
            default -> {
                LOGGER.info(
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "F2F unexpected status: " + faceToFaceRequest.getStatus()));
                return JOURNEY_F2F_FAIL;
            }
        }
    }

    private Map<String, Object> buildCiBreachingResponse(ContraIndicators contraIndicators)
            throws UnrecognisedCiException, ConfigException {
        JourneyResponse journeyResponse = JOURNEY_FAIL_WITH_CI;

        var cimitConfig = configService.getCimitConfig();
        for (var ci : contraIndicators.getContraIndicatorsMap().values()) {
            if (cimitConfig.containsKey(ci.getCode()) && !ci.isMitigated()) {
                journeyResponse = new JourneyResponse(cimitConfig.get(ci.getCode()));
                break;
            }
        }

        StringMapMessage message = new StringMapMessage();
        message.with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "Returning CI error response.")
                .with(LOG_ERROR_JOURNEY_RESPONSE.getFieldName(), journeyResponse.toString());
        LOGGER.info(message);

        return journeyResponse.toObjectMap();
    }

    private Map<String, Object> buildF2FNotCorrelatedResponse(AuditEventUser auditEventUser)
            throws SqsException {
        var message =
                new StringMapMessage()
                        .with(
                                LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                "F2F return - failed to correlate VC data");
        LOGGER.info(message);

        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_F2F_CORRELATION_FAIL,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser));

        return JOURNEY_F2F_FAIL;
    }

    private Map<String, Object> buildNotCorrelatedResponse(AuditEventUser auditEventUser)
            throws SqsException {
        LOGGER.info(
                new StringMapMessage()
                        .with(
                                LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                "VC data does not correlate so resetting identity."));

        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_IDENTITY_REUSE_RESET,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser));

        return JOURNEY_RESET_IDENTITY;
    }

    private Map<String, Object> buildForceResetResponse() {
        LOGGER.info("resetIdentity flag is enabled, reset users identity.");
        return JOURNEY_RESET_IDENTITY;
    }

    private Map<String, Object> buildF2FNoMatchResponse(AuditEventUser auditEventUser)
            throws SqsException {
        var message =
                new StringMapMessage()
                        .with(
                                LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                "F2F return - failed to match a profile.");
        LOGGER.info(message);

        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_F2F_PROFILE_NOT_MET_FAIL,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser));

        return JOURNEY_F2F_FAIL;
    }

    private Map<String, Object> buildNoMatchResponse(
            List<SignedJWT> credentials, AuditEventUser auditEventUser) throws SqsException {
        if (!credentials.isEmpty()) {
            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Failed to match profile so resetting identity.");
            LOGGER.info(message);

            auditService.sendAuditEvent(
                    new AuditEvent(
                            AuditEventTypes.IPV_IDENTITY_REUSE_RESET,
                            configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser));

            return JOURNEY_RESET_IDENTITY;
        }
        var message =
                new StringMapMessage()
                        .with(
                                LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                "New user so returning next.");
        LOGGER.info(message);

        return JOURNEY_NEXT;
    }

    private Map<String, Object> buildProfileMatchedResponse(
            Gpg45Profile matchedProfile, AuditEventUser auditEventUser) throws SqsException {
        var message =
                new StringMapMessage()
                        .with(
                                LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                "Matched profile and within CI threshold so returning reuse journey.")
                        .with(LOG_PROFILE.getFieldName(), matchedProfile.getLabel());
        LOGGER.info(message);

        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser));

        return JOURNEY_REUSE;
    }

    private Map<String, Object> buildErrorResponse(ErrorResponse errorResponse, Exception e) {
        LOGGER.error(errorResponse.getMessage(), e);
        return new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH, HttpStatus.SC_INTERNAL_SERVER_ERROR, errorResponse)
                .toObjectMap();
    }

    @Tracing
    private void sendProfileMatchedAuditEvent(
            Gpg45Profile gpg45Profile,
            Gpg45Scores gpg45Scores,
            List<SignedJWT> credentials,
            AuditEventUser auditEventUser)
            throws ParseException, SqsException {
        var auditEvent =
                new AuditEvent(
                        AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditExtensionGpg45ProfileMatched(
                                gpg45Profile,
                                gpg45Scores,
                                extractTxnIdsFromCredentials(credentials)));
        auditService.sendAuditEvent(auditEvent);
    }

    @Tracing
    private List<String> extractTxnIdsFromCredentials(List<SignedJWT> credentials)
            throws ParseException {
        List<String> txnIds = new ArrayList<>();
        for (SignedJWT credential : credentials) {
            var jwtClaimsSet = credential.getJWTClaimsSet();
            var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
            var evidences = (JSONArray) vc.get(VC_EVIDENCE);
            if (evidences != null) { // not all VCs have an evidence block
                var evidence = (JSONObject) evidences.get(ONLY);
                txnIds.add(evidence.getAsString(VC_EVIDENCE_TXN));
            }
        }
        return txnIds;
    }

    @Tracing
    private boolean vcDataCorrelates(String userId)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        StringJoiner uncorrelatableData = new StringJoiner(",");
        if (!userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(userId)) {
            uncorrelatableData.add(NAMES);
        }

        if (!userIdentityService.checkBirthDateCorrelationInCredentials(userId)) {
            uncorrelatableData.add(DATE_OF_BIRTH);
        }

        if (uncorrelatableData.length() > 0) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_ERROR_CODE.getFieldName(),
                                    ErrorResponse.FAILED_TO_CORRELATE_DATA.getCode())
                            .with(
                                    LOG_ERROR_DESCRIPTION.getFieldName(),
                                    ErrorResponse.FAILED_TO_CORRELATE_DATA.getMessage())
                            .with(LOG_UNCORRELATABLE_DATA.getFieldName(), uncorrelatableData));
            return false;
        }
        return true;
    }
}
