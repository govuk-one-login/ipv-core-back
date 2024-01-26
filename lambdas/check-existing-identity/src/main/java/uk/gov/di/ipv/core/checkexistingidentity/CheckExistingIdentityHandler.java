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
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.enums.OperationalProfile;
import uk.gov.di.ipv.core.library.enums.Vot;
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
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.RESET_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_TXN;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_VOT;
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
    public static final List<Vot> SUPPORTED_VOTS_BY_STRENGTH =
            List.of(Vot.P2, Vot.PCL250, Vot.PCL200);
    public static final String VOT_CLAIM = "vot";

    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final CriResponseService criResponseService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final AuditService auditService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CiMitService ciMitService;
    private final CiMitUtilityService ciMitUtilityService;
    private final VerifiableCredentialService verifiableCredentialService;

    @SuppressWarnings({
        "unused",
        "java:S107"
    }) // Used by AWS, methods should not have too many parameters
    public CheckExistingIdentityHandler(
            ConfigService configService,
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            AuditService auditService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService,
            CiMitService ciMitService,
            CiMitUtilityService ciMitUtilityService,
            VerifiableCredentialService verifiableCredentialService) {
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.auditService = auditService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
        this.ciMitService = ciMitService;
        this.ciMitUtilityService = ciMitUtilityService;
        this.verifiableCredentialService = verifiableCredentialService;
        VcHelper.setConfigService(this.configService);
    }

    @SuppressWarnings("unused") // Used through dependency injection
    @ExcludeFromGeneratedCoverageReport
    public CheckExistingIdentityHandler() {
        this.configService = new ConfigService();
        this.userIdentityService = new UserIdentityService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.criResponseService = new CriResponseService(configService);
        this.ciMitService = new CiMitService(configService);
        this.ciMitUtilityService = new CiMitUtilityService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        VcHelper.setConfigService(this.configService);
    }

    @SuppressWarnings("java:S3776") // Cognitive Complexity of methods should not be too high
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

            // Clear TICF VCs
            verifiableCredentialService.deleteVcStoreItem(userId, TICF_CRI);

            // Reset identity if reprove is true.
            Boolean reproveIdentity = clientOAuthSessionItem.getReproveIdentity();
            if (reproveIdentity != null && reproveIdentity) {
                return buildForceResetResponse();
            }

            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            AuditEventUser auditEventUser =
                    new AuditEventUser(userId, ipvSessionId, govukSigninJourneyId, ipAddress);

            CriResponseItem f2fRequest = criResponseService.getFaceToFaceRequest(userId);

            List<VcStoreItem> vcStoreItems = verifiableCredentialService.getVcStoreItems(userId);
            var hasF2fVc =
                    vcStoreItems.stream()
                            .anyMatch(
                                    vcStoreItem ->
                                            vcStoreItem.getCredentialIssuer().equals(F2F_CRI));

            final boolean isF2FIncomplete = !Objects.isNull(f2fRequest) && !hasF2fVc;
            final boolean isF2FComplete = !Objects.isNull(f2fRequest) && hasF2fVc;

            // Incomplete F2F journey
            if (isF2FIncomplete) {
                return buildF2FIncompleteResponse(f2fRequest);
            }

            var contraIndicators =
                    ciMitService.getContraIndicatorsVC(
                            clientOAuthSessionItem.getUserId(), govukSigninJourneyId, ipAddress);

            // CI scoring failure
            if (ciMitUtilityService.isBreachingCiThreshold(contraIndicators)) {
                return ciMitUtilityService
                        .getCiMitigationJourneyStep(contraIndicators)
                        .orElse(JOURNEY_FAIL_WITH_CI)
                        .toObjectMap();
            }

            List<SignedJWT> credentials =
                    gpg45ProfileEvaluator.parseCredentials(
                            userIdentityService.getIdentityCredentials(vcStoreItems));

            // Credential correlation failure
            if (!userIdentityService.areVCsCorrelated(vcStoreItems)) {
                return isF2FComplete
                        ? buildF2FNotCorrelatedResponse(auditEventUser)
                        : buildNotCorrelatedResponse(auditEventUser);
            }

            // Force reset
            if (configService.enabled(RESET_IDENTITY.getName())) {
                return buildForceResetResponse();
            }

            // Check for attained vot from vtr
            var attainedVot =
                    getAttainedVot(
                            clientOAuthSessionItem.getVtr(),
                            credentials,
                            vcStoreItems,
                            auditEventUser);

            // vot achieved
            if (attainedVot.isPresent()) {
                ipvSessionItem.setVot(attainedVot.get().name());
                ipvSessionService.updateIpvSession(ipvSessionItem);

                return buildReuseResponse(auditEventUser);
            }

            // No profile match
            return isF2FComplete
                    ? buildF2FNoMatchResponse(auditEventUser)
                    : buildNoMatchResponse(vcStoreItems, auditEventUser);

        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error(LogHelper.buildErrorMessage(e.getErrorResponse().getMessage(), e));
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
                LOGGER.info(LogHelper.buildLogMessage("F2F cri pending verification."));
                return JOURNEY_PENDING;
            }
            case CriResponseService.STATUS_ERROR -> {
                LOGGER.warn(LogHelper.buildLogMessage("F2F cri error."));
                return JOURNEY_F2F_FAIL;
            }
            default -> {
                LOGGER.warn(
                        LogHelper.buildLogMessage(
                                "F2F unexpected status: " + faceToFaceRequest.getStatus()));
                return JOURNEY_F2F_FAIL;
            }
        }
    }

    private Map<String, Object> buildF2FNotCorrelatedResponse(AuditEventUser auditEventUser)
            throws SqsException {
        LOGGER.warn(LogHelper.buildLogMessage("F2F return - failed to correlate VC data."));

        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_F2F_CORRELATION_FAIL,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser));

        return JOURNEY_F2F_FAIL;
    }

    private Map<String, Object> buildNotCorrelatedResponse(AuditEventUser auditEventUser)
            throws SqsException {
        LOGGER.info(LogHelper.buildLogMessage("VC data does not correlate so resetting identity."));
        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_IDENTITY_REUSE_RESET,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser));

        return JOURNEY_RESET_IDENTITY;
    }

    private Map<String, Object> buildForceResetResponse() {
        LOGGER.info(
                LogHelper.buildLogMessage("resetIdentity flag is enabled, reset users identity."));
        return JOURNEY_RESET_IDENTITY;
    }

    private Map<String, Object> buildF2FNoMatchResponse(AuditEventUser auditEventUser)
            throws SqsException {
        LOGGER.info(LogHelper.buildLogMessage("F2F return - failed to match a profile."));

        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_F2F_PROFILE_NOT_MET_FAIL,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser));

        return JOURNEY_F2F_FAIL;
    }

    private Map<String, Object> buildNoMatchResponse(
            List<VcStoreItem> vcStoreItems, AuditEventUser auditEventUser) throws SqsException {
        if (!VcHelper.filterVCBasedOnProfileType(vcStoreItems, ProfileType.GPG45).isEmpty()) {
            LOGGER.info(
                    LogHelper.buildLogMessage("Failed to match profile so resetting identity."));

            auditService.sendAuditEvent(
                    new AuditEvent(
                            AuditEventTypes.IPV_IDENTITY_REUSE_RESET,
                            configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                            auditEventUser));

            return JOURNEY_RESET_IDENTITY;
        }
        LOGGER.info(LogHelper.buildLogMessage("New IPV journey required, returning journey next"));
        return JOURNEY_NEXT;
    }

    private Map<String, Object> buildReuseResponse(AuditEventUser auditEventUser)
            throws SqsException {
        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser));

        LOGGER.info(LogHelper.buildLogMessage("Returning reuse journey"));
        return JOURNEY_REUSE;
    }

    private Map<String, Object> buildErrorResponse(ErrorResponse errorResponse, Exception e) {
        LOGGER.error(LogHelper.buildErrorMessage(errorResponse.getMessage(), e));
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
    private Optional<Vot> getAttainedVot(
            List<String> vtr,
            List<SignedJWT> credentials,
            List<VcStoreItem> vcStoreItems,
            AuditEventUser auditEventUser)
            throws UnknownEvidenceTypeException, ParseException, SqsException {

        var requestedVotsByStrength =
                SUPPORTED_VOTS_BY_STRENGTH.stream()
                        .filter(vot -> vtr.contains(vot.name()))
                        .toList();

        for (var requestedVot : requestedVotsByStrength) {
            var requestedVotAttained =
                    requestedVot.getProfileType().equals(ProfileType.GPG45)
                            ? achievedWithGpg45Profile(
                                    requestedVot, credentials, vcStoreItems, auditEventUser)
                            : hasOperationalProfileVc(requestedVot, credentials);

            if (requestedVotAttained) {
                return Optional.of(requestedVot);
            }
        }
        return Optional.empty();
    }

    private boolean achievedWithGpg45Profile(
            Vot requestedVot,
            List<SignedJWT> credentials,
            List<VcStoreItem> vcStoreItems,
            AuditEventUser auditEventUser)
            throws UnknownEvidenceTypeException, ParseException, SqsException {

        Gpg45Scores gpg45Scores = gpg45ProfileEvaluator.buildScore(credentials);
        Optional<Gpg45Profile> matchedGpg45Profile =
                !userIdentityService.checkRequiresAdditionalEvidence(vcStoreItems)
                        ? gpg45ProfileEvaluator.getFirstMatchingProfile(
                                gpg45Scores, requestedVot.getSupportedGpg45Profiles())
                        : Optional.empty();

        // Successful match
        if (matchedGpg45Profile.isPresent()) {
            sendProfileMatchedAuditEvent(
                    matchedGpg45Profile.get(), gpg45Scores, credentials, auditEventUser);

            return true;
        }
        return false;
    }

    private boolean hasOperationalProfileVc(Vot requestedVot, List<SignedJWT> credentials)
            throws ParseException {
        for (SignedJWT cred : credentials) {
            String credentialVot = cred.getJWTClaimsSet().getStringClaim(VOT_CLAIM);
            Optional<String> matchedOperationalProfile =
                    requestedVot.getSupportedOperationalProfiles().stream()
                            .map(OperationalProfile::name)
                            .filter(profileName -> profileName.equals(credentialVot))
                            .findFirst();

            // Successful match
            if (matchedOperationalProfile.isPresent()) {
                LOGGER.info(
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "Operational profile matched")
                                .with(LOG_VOT.getFieldName(), requestedVot));
                return true;
            }
        }
        return false;
    }
}
