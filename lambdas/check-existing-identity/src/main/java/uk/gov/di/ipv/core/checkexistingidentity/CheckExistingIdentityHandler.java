package uk.gov.di.ipv.core.checkexistingidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.checkexistingidentity.exceptions.MitigationRouteException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionGpg45ProfileMatched;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.EvcsService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.service.VotMatcher;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.model.ContraIndicator;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static com.amazonaws.util.CollectionUtils.isNullOrEmpty;
import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_NOT_FOUND;
import static java.lang.Boolean.TRUE;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.REPEAT_FRAUD_CHECK;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.RESET_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.ProfileType.GPG45;
import static uk.gov.di.ipv.core.library.domain.ProfileType.OPERATIONAL_HMRC;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ENHANCED_VERIFICATION_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IN_MIGRATION_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IPV_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IPV_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_PENDING_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REPEAT_FRAUD_CHECK_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REUSE_WITH_STORE_PATH;
import static uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper.filterVCBasedOnProfileType;

/** Check Existing Identity response Lambda */
public class CheckExistingIdentityHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final JourneyResponse JOURNEY_REUSE = new JourneyResponse(JOURNEY_REUSE_PATH);
    private static final JourneyResponse JOURNEY_REUSE_WITH_STORE =
            new JourneyResponse(JOURNEY_REUSE_WITH_STORE_PATH);
    private static final JourneyResponse JOURNEY_OPERATIONAL_PROFILE_REUSE =
            new JourneyResponse(JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH);
    private static final JourneyResponse JOURNEY_IN_MIGRATION_REUSE =
            new JourneyResponse(JOURNEY_IN_MIGRATION_REUSE_PATH);
    private static final JourneyResponse JOURNEY_PENDING =
            new JourneyResponse(JOURNEY_PENDING_PATH);
    private static final JourneyResponse JOURNEY_IPV_GPG45_LOW =
            new JourneyResponse(JOURNEY_IPV_GPG45_LOW_PATH);
    private static final JourneyResponse JOURNEY_IPV_GPG45_MEDIUM =
            new JourneyResponse(JOURNEY_IPV_GPG45_MEDIUM_PATH);
    private static final JourneyResponse JOURNEY_F2F_FAIL =
            new JourneyResponse(JOURNEY_F2F_FAIL_PATH);
    private static final JourneyResponse JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL =
            new JourneyResponse(JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL_PATH);
    private static final JourneyResponse JOURNEY_REPEAT_FRAUD_CHECK =
            new JourneyResponse(JOURNEY_REPEAT_FRAUD_CHECK_PATH);
    private static final JourneyResponse JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM =
            new JourneyResponse(JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH);
    private static final JourneyResponse JOURNEY_REPROVE_IDENTITY_GPG45_LOW =
            new JourneyResponse(JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH);

    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final CriResponseService criResponseService;
    private final IpvSessionService ipvSessionService;
    private final AuditService auditService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CimitService cimitService;
    private final CimitUtilityService cimitUtilityService;
    private final SessionCredentialsService sessionCredentialsService;
    private final EvcsService evcsService;
    private final VotMatcher votMatcher;

    @SuppressWarnings({
        "unused",
        "java:S107"
    }) // Used by AWS, methods should not have too many parameters
    public CheckExistingIdentityHandler(
            ConfigService configService,
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            AuditService auditService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService,
            CimitService cimitService,
            CimitUtilityService cimitUtilityService,
            VerifiableCredentialService verifiableCredentialService,
            SessionCredentialsService sessionCredentialsService,
            EvcsService evcsService,
            VotMatcher votMatcher) {
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.auditService = auditService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
        this.cimitService = cimitService;
        this.cimitUtilityService = cimitUtilityService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.evcsService = evcsService;
        this.votMatcher = votMatcher;
        VcHelper.setConfigService(this.configService);
    }

    @SuppressWarnings("unused") // Used through dependency injection
    @ExcludeFromGeneratedCoverageReport
    public CheckExistingIdentityHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckExistingIdentityHandler(ConfigService configService) {
        this.configService = ConfigService.create();
        this.userIdentityService = new UserIdentityService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.auditService = AuditService.create(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.criResponseService = new CriResponseService(configService);
        this.cimitService = new CimitService(configService);
        this.cimitUtilityService = new CimitUtilityService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.evcsService = new EvcsService(configService);
        this.votMatcher =
                new VotMatcher(
                        userIdentityService, new Gpg45ProfileEvaluator(), cimitUtilityService);
        VcHelper.setConfigService(this.configService);
    }

    private record VerifiableCredentialBundle(
            List<VerifiableCredential> credentials, boolean isPendingIdentity) {
        private boolean isF2fIdentity() {
            return credentials.stream().anyMatch(vc -> vc.getCri().equals(F2F));
        }
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest event, Context context) {
        LogHelper.attachComponentId(configService);

        try {
            String ipvSessionId = getIpvSessionId(event);
            String ipAddress = getIpAddress(event);
            String deviceInformation = event.getDeviceInformation();
            configService.setFeatureSet(RequestHelper.getFeatureSet(event));

            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSessionWithRetry(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());

            return getJourneyResponse(
                            ipvSessionItem, clientOAuthSessionItem, ipAddress, deviceInformation)
                    .toObjectMap();
        } catch (HttpResponseExceptionWithErrorBody e) {
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (IpvSessionNotFoundException e) {
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, SC_NOT_FOUND, ErrorResponse.IPV_SESSION_NOT_FOUND)
                    .toObjectMap();
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        } finally {
            auditService.awaitAuditEvents();
        }
    }

    @SuppressWarnings({
        "java:S3776", // Cognitive Complexity of methods should not be too high
        "java:S6541" // "Brain method" PYIC-6901 should refactor this method
    })
    private JourneyResponse getJourneyResponse(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String ipAddress,
            String deviceInformation) {
        try {
            var ipvSessionId = ipvSessionItem.getIpvSessionId();
            var userId = clientOAuthSessionItem.getUserId();
            var govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();

            var auditEventUser =
                    new AuditEventUser(userId, ipvSessionId, govukSigninJourneyId, ipAddress);

            var credentialBundle =
                    getCredentialBundle(userId, clientOAuthSessionItem.getEvcsAccessToken());
            var f2fResponseItem = criResponseService.getFaceToFaceRequest(userId);
            final boolean hasF2fVc = credentialBundle.isF2fIdentity();
            final boolean hasF2fRequest = !Objects.isNull(f2fResponseItem);
            final boolean isF2FIncomplete = hasF2fRequest && !hasF2fVc;
            final boolean isF2FComplete =
                    hasF2fRequest && hasF2fVc && credentialBundle.isPendingIdentity();

            // If we want to prove or mitigate CIs for an identity we want to go for the lowest
            // strength that is acceptable to the caller. We can only prove/mitigate GPG45
            // identities
            var lowestGpg45ConfidenceRequested =
                    clientOAuthSessionItem
                            .getParsedVtr()
                            .getLowestStrengthRequestedGpg45Vot(configService);

            // As almost all of our journeys are proving or mitigating a GPG45 vot we set the
            // target vot here as a default value. It will be overridden for identity reuse.
            ipvSessionItem.setTargetVot(lowestGpg45ConfidenceRequested);
            ipvSessionService.updateIpvSession(ipvSessionItem);

            var contraIndicators =
                    cimitService.getContraIndicators(
                            clientOAuthSessionItem.getUserId(), govukSigninJourneyId, ipAddress);

            var reproveIdentity = TRUE.equals(clientOAuthSessionItem.getReproveIdentity());
            // Don't start a new reprove journey if user is returning from F2F reprove journey
            if (reproveIdentity && !isReprovingWithF2f(f2fResponseItem, credentialBundle)
                    || configService.enabled(RESET_IDENTITY)) {
                if (lowestGpg45ConfidenceRequested == Vot.P1) {
                    LOGGER.info(LogHelper.buildLogMessage("Reproving P1 identity"));
                    return JOURNEY_REPROVE_IDENTITY_GPG45_LOW;
                }

                LOGGER.info(LogHelper.buildLogMessage("Reproving P2 identity"));
                return JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM;
            }

            // PYIC-6901 Currently we just check against the lowest Vot requested for this journey.
            // That might cause an issue if a user needs to mitigate a P2 journey but comes back to
            // us with a P1 request that doesn't need mitigation. This is out of scope for the MVP
            // though.
            var ciScoringCheckResponse =
                    cimitUtilityService.getMitigationJourneyIfBreaching(
                            contraIndicators, lowestGpg45ConfidenceRequested);
            if (ciScoringCheckResponse.isPresent()) {
                return isF2FIncomplete
                        ? buildF2FIncompleteResponse(
                                f2fResponseItem) // F2F mitigation journey in progress
                        : ciScoringCheckResponse.get(); // CI fail or mitigation journey
            }

            // Check for credentials correlation failure
            var areGpg45VcsCorrelated =
                    userIdentityService.areVcsCorrelated(credentialBundle.credentials);

            var profileMatchResponse =
                    checkForProfileMatch(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            auditEventUser,
                            deviceInformation,
                            credentialBundle,
                            areGpg45VcsCorrelated,
                            contraIndicators);
            if (profileMatchResponse.isPresent()) {
                // We are re-using an existing Vot, so it might not be a GPG45 vot
                ipvSessionItem.setTargetVot(
                        clientOAuthSessionItem
                                .getParsedVtr()
                                .getLowestStrengthRequestedVot(configService));
                ipvSessionService.updateIpvSession(ipvSessionItem);
                removeReproveIdentityFlag(f2fResponseItem);
                return profileMatchResponse.get();
            }

            // No profile matched but has a pending F2F request
            if (isF2FIncomplete) {
                return buildF2FIncompleteResponse(f2fResponseItem);
            }

            removeReproveIdentityFlag(f2fResponseItem);

            // No profile match
            return isF2FComplete
                    ? buildF2FNoMatchResponse(
                            areGpg45VcsCorrelated,
                            auditEventUser,
                            deviceInformation,
                            contraIndicators)
                    : buildNoMatchResponse(contraIndicators, lowestGpg45ConfidenceRequested);
        } catch (HttpResponseExceptionWithErrorBody
                | VerifiableCredentialException
                | EvcsServiceException e) {
            return buildErrorResponse(e.getErrorResponse(), e);
        } catch (CiRetrievalException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_GET_STORED_CIS, e);
        } catch (ParseException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS, e);
        } catch (CredentialParseException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS, e);
        } catch (ConfigException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_PARSE_CONFIG, e);
        } catch (UnrecognisedCiException e) {
            return buildErrorResponse(ErrorResponse.UNRECOGNISED_CI_CODE, e);
        } catch (MitigationRouteException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_FIND_MITIGATION_ROUTE, e);
        }
    }

    private VerifiableCredentialBundle getCredentialBundle(String userId, String evcsAccessToken)
            throws CredentialParseException, EvcsServiceException {
        var vcs =
                evcsService.getVerifiableCredentialsByState(
                        userId, evcsAccessToken, CURRENT, PENDING_RETURN);

        if (vcs.isEmpty()) {
            return new VerifiableCredentialBundle(List.of(), false);
        }

        // Use pending return vcs to determine identity if available
        var evcsIdentityVcs = vcs.get(PENDING_RETURN);
        var isPending = true;
        if (isNullOrEmpty(evcsIdentityVcs)) {
            evcsIdentityVcs = vcs.get(CURRENT);
            isPending = false;
        } else {
            // Ensure we keep any inherited ID VCs in the bundle
            evcsIdentityVcs.addAll(
                    vcs.getOrDefault(CURRENT, List.of()).stream()
                            .filter(vc -> HMRC_MIGRATION.equals(vc.getCri()))
                            .toList());
        }

        return new VerifiableCredentialBundle(evcsIdentityVcs, isPending);
    }

    private JourneyResponse buildF2FIncompleteResponse(CriResponseItem faceToFaceRequest) {
        switch (faceToFaceRequest.getStatus()) {
            case CriResponseService.STATUS_PENDING -> {
                LOGGER.info(LogHelper.buildLogMessage("F2F cri pending verification."));
                return JOURNEY_PENDING;
            }
            case CriResponseService.STATUS_ABANDON -> {
                LOGGER.info(LogHelper.buildLogMessage("F2F cri abandon."));
                return JOURNEY_F2F_FAIL;
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

    private Optional<JourneyResponse> checkForProfileMatch(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            AuditEventUser auditEventUser,
            String deviceInformation,
            VerifiableCredentialBundle credentialBundle,
            boolean areGpg45VcsCorrelated,
            List<ContraIndicator> contraIndicators)
            throws ParseException, VerifiableCredentialException {
        // Check for attained vot from requested vots
        var maybeVotMatchingResult =
                votMatcher.matchFirstVot(
                        clientOAuthSessionItem
                                .getParsedVtr()
                                .getRequestedVotsByStrengthDescending(),
                        credentialBundle.credentials(),
                        contraIndicators,
                        areGpg45VcsCorrelated);

        if (maybeVotMatchingResult.isEmpty()) {
            return Optional.empty();
        }

        var votMatchingResult = maybeVotMatchingResult.get();

        if (GPG45.equals(votMatchingResult.vot().getProfileType())) {
            sendProfileMatchedAuditEvent(
                    votMatchingResult.gpg45Profile(),
                    votMatchingResult.gpg45Scores(),
                    VcHelper.filterVCBasedOnProfileType(credentialBundle.credentials(), GPG45),
                    auditEventUser,
                    deviceInformation);
        }

        // vot achieved for vtr
        return Optional.of(
                buildReuseResponse(
                        votMatchingResult.vot(),
                        ipvSessionItem,
                        credentialBundle,
                        auditEventUser,
                        deviceInformation));
    }

    private JourneyResponse buildF2FNoMatchResponse(
            boolean areGpg45VcsCorrelated,
            AuditEventUser auditEventUser,
            String deviceInformation,
            List<ContraIndicator> contraIndicators)
            throws ConfigException, MitigationRouteException {
        LOGGER.info(LogHelper.buildLogMessage("F2F return - failed to match a profile."));
        sendAuditEvent(
                !areGpg45VcsCorrelated
                        ? AuditEventTypes.IPV_F2F_CORRELATION_FAIL
                        : AuditEventTypes.IPV_F2F_PROFILE_NOT_MET_FAIL,
                auditEventUser,
                deviceInformation);
        var mitigatedCI = cimitUtilityService.hasMitigatedContraIndicator(contraIndicators);
        if (mitigatedCI.isPresent()) {
            var mitigationJourney =
                    cimitUtilityService
                            .getMitigatedCiJourneyResponse(mitigatedCI.get())
                            .map(JourneyResponse::getJourney)
                            .orElseThrow(
                                    () ->
                                            new MitigationRouteException(
                                                    String.format(
                                                            "Empty mitigation route for mitigated CI: %s",
                                                            mitigatedCI.get())));
            if (!JOURNEY_ENHANCED_VERIFICATION_PATH.equals(mitigationJourney)) {
                throw new MitigationRouteException(
                        String.format("Unsupported mitigation route: %s", mitigationJourney));
            }
            return JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL;
        }
        return JOURNEY_F2F_FAIL;
    }

    private JourneyResponse buildNoMatchResponse(
            List<ContraIndicator> contraIndicators, Vot preferredNewIdentityLevel)
            throws ConfigException, MitigationRouteException {

        var mitigatedCI = cimitUtilityService.hasMitigatedContraIndicator(contraIndicators);
        if (mitigatedCI.isPresent()) {
            return cimitUtilityService
                    .getMitigatedCiJourneyResponse(mitigatedCI.get())
                    .orElseThrow(
                            () ->
                                    new MitigationRouteException(
                                            String.format(
                                                    "Empty mitigation route for mitigated CI: %s",
                                                    mitigatedCI.get())));
        }

        if (preferredNewIdentityLevel == Vot.P1) {
            LOGGER.info(LogHelper.buildLogMessage("New P1 IPV journey required"));
            return JOURNEY_IPV_GPG45_LOW;
        }

        LOGGER.info(LogHelper.buildLogMessage("New P2 IPV journey required"));
        return JOURNEY_IPV_GPG45_MEDIUM;
    }

    private JourneyResponse buildReuseResponse(
            Vot attainedVot,
            IpvSessionItem ipvSessionItem,
            VerifiableCredentialBundle credentialBundle,
            AuditEventUser auditEventUser,
            String deviceInformation)
            throws VerifiableCredentialException {
        // check the result of 6MFC and return the appropriate journey
        if (configService.enabled(REPEAT_FRAUD_CHECK)
                && attainedVot.getProfileType() == GPG45
                && allFraudVcsAreExpired(credentialBundle.credentials)) {
            LOGGER.info(LogHelper.buildLogMessage("Expired fraud VC found"));
            sessionCredentialsService.persistCredentials(
                    allVcsExceptFraud(credentialBundle.credentials),
                    auditEventUser.getSessionId(),
                    false);

            return JOURNEY_REPEAT_FRAUD_CHECK;
        }

        LOGGER.info(LogHelper.buildLogMessage("Returning reuse journey"));
        sendAuditEvent(
                AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE, auditEventUser, deviceInformation);

        ipvSessionItem.setVot(attainedVot);
        ipvSessionService.updateIpvSession(ipvSessionItem);

        if (attainedVot.getProfileType() == OPERATIONAL_HMRC) {
            boolean isCurrentlyMigrating = ipvSessionItem.isInheritedIdentityReceivedThisSession();

            sessionCredentialsService.persistCredentials(
                    filterVCBasedOnProfileType(credentialBundle.credentials, OPERATIONAL_HMRC),
                    auditEventUser.getSessionId(),
                    isCurrentlyMigrating);

            return isCurrentlyMigrating
                    ? JOURNEY_IN_MIGRATION_REUSE
                    : JOURNEY_OPERATIONAL_PROFILE_REUSE;
        }

        sessionCredentialsService.persistCredentials(
                filterVCBasedOnProfileType(
                        credentialBundle.credentials, attainedVot.getProfileType()),
                auditEventUser.getSessionId(),
                false);

        return credentialBundle.isPendingIdentity() ? JOURNEY_REUSE_WITH_STORE : JOURNEY_REUSE;
    }

    private List<VerifiableCredential> allVcsExceptFraud(List<VerifiableCredential> vcs) {
        return vcs.stream().filter(vc -> !EXPERIAN_FRAUD.equals(vc.getCri())).toList();
    }

    private boolean allFraudVcsAreExpired(List<VerifiableCredential> vcs) {
        return vcs.stream()
                .filter(vc -> vc.getCri() == EXPERIAN_FRAUD)
                .allMatch(VcHelper::isExpiredFraudVc);
    }

    private void sendAuditEvent(
            AuditEventTypes auditEventTypes,
            AuditEventUser auditEventUser,
            String deviceInformation) {
        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        auditEventTypes,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditRestrictedDeviceInformation(deviceInformation)));
    }

    private JourneyResponse buildErrorResponse(ErrorResponse errorResponse, Exception e) {
        LOGGER.error(LogHelper.buildErrorMessage(errorResponse.getMessage(), e));
        return new JourneyErrorResponse(
                JOURNEY_ERROR_PATH, HttpStatus.SC_INTERNAL_SERVER_ERROR, errorResponse);
    }

    private void sendProfileMatchedAuditEvent(
            Gpg45Profile gpg45Profile,
            Gpg45Scores gpg45Scores,
            List<VerifiableCredential> vcs,
            AuditEventUser auditEventUser,
            String deviceInformation) {
        var auditEvent =
                AuditEvent.createWithDeviceInformation(
                        AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditExtensionGpg45ProfileMatched(
                                gpg45Profile,
                                gpg45Scores,
                                VcHelper.extractTxnIdsFromCredentials(vcs)),
                        new AuditRestrictedDeviceInformation(deviceInformation));
        auditService.sendAuditEvent(auditEvent);
    }

    private boolean isReprovingWithF2f(
            CriResponseItem f2fRequest, VerifiableCredentialBundle vcBundle) {
        // does the user have a F2F response item that was created in response to an intervention,
        // and they're returning to core with a pending identity
        return f2fRequest != null && f2fRequest.isReproveIdentity() && vcBundle.isPendingIdentity();
    }

    private void removeReproveIdentityFlag(CriResponseItem f2fResponseItem) {
        if (f2fResponseItem != null && f2fResponseItem.isReproveIdentity()) {
            // Remove the reprove identity flag, so we won't skip reprove identity on a future
            // journey
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Removing reprove identity flag from F2F CRI response item"));
            f2fResponseItem.setReproveIdentity(false);
            criResponseService.updateCriResponseItem(f2fResponseItem);
        }
    }
}
