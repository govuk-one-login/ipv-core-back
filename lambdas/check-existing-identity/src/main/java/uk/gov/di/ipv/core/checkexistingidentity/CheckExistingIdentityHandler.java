package uk.gov.di.ipv.core.checkexistingidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.checkexistingidentity.exceptions.MitigationRouteException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionGpg45ProfileMatched;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionPreviousIpvSessionId;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.criresponse.domain.AsyncCriStatus;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
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
import uk.gov.di.ipv.core.library.helpers.VotHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatcher;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.model.ContraIndicator;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_NOT_FOUND;
import static java.lang.Boolean.TRUE;
import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.PROCESS_CANDIDATE_IDENTITY;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.REPEAT_FRAUD_CHECK;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.RESET_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.ProfileType.GPG45;
import static uk.gov.di.ipv.core.library.domain.ProfileType.OPERATIONAL_HMRC;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ENHANCED_VERIFICATION_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IN_MIGRATION_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IPV_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IPV_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH;
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
    private static final JourneyResponse JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW =
            new JourneyResponse(JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW_PATH);
    private static final JourneyResponse JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM =
            new JourneyResponse(JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM_PATH);

    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final CriResponseService criResponseService;
    private final CriOAuthSessionService criOAuthSessionService;
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
            SessionCredentialsService sessionCredentialsService,
            CriOAuthSessionService criOAuthSessionService,
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
        this.criOAuthSessionService = criOAuthSessionService;
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
        this.criOAuthSessionService = new CriOAuthSessionService(configService);
        this.votMatcher =
                new VotMatcher(
                        userIdentityService, new Gpg45ProfileEvaluator(), cimitUtilityService);
        VcHelper.setConfigService(this.configService);
    }

    private record VerifiableCredentialBundle(
            List<VerifiableCredential> credentials, boolean isPendingReturn) {}

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
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

            var evcsAccessToken = clientOAuthSessionItem.getEvcsAccessToken();
            var credentialBundle = getCredentialBundle(userId, evcsAccessToken);

            var asyncCriStatus =
                    criResponseService.getAsyncResponseStatus(
                            userId, credentialBundle.credentials, credentialBundle.isPendingReturn);

            var targetVot = VotHelper.getThresholdVot(ipvSessionItem, clientOAuthSessionItem);

            var contraIndicatorsVc =
                    cimitService.getContraIndicatorsVc(
                            clientOAuthSessionItem.getUserId(),
                            govukSigninJourneyId,
                            ipAddress,
                            ipvSessionItem);

            var contraIndicators =
                    cimitUtilityService.getContraIndicatorsFromVc(contraIndicatorsVc);

            var reproveIdentity = TRUE.equals(clientOAuthSessionItem.getReproveIdentity());
            // Only skip starting a new reprove identity journey if the user is returning from a F2F
            // journey
            if (reproveIdentity && !isReprovingWithF2f(asyncCriStatus, credentialBundle)
                    || configService.enabled(RESET_IDENTITY)) {
                if (targetVot == Vot.P1) {
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
                            contraIndicators, targetVot);
            if (ciScoringCheckResponse.isPresent()) {
                if (asyncCriStatus.isAwaitingVc()) {
                    return asyncCriStatus.getJourneyForAwaitingVc(false);
                }
                return ciScoringCheckResponse.get();
            }

            // No breaching CIs.

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
                return profileMatchResponse.get();
            }

            // No profile matched.

            if (asyncCriStatus.isAwaitingVc()) {
                return asyncCriStatus.getJourneyForAwaitingVc(false);
            }

            // No awaited async vc.

            if (asyncCriStatus.isPendingReturn()) {
                if (asyncCriStatus.cri() == F2F) {

                    // Returned with F2F async VC. Should have matched a profile.

                    return buildF2FNoMatchResponse(
                            areGpg45VcsCorrelated,
                            auditEventUser,
                            deviceInformation,
                            contraIndicators);
                }
                if (asyncCriStatus.cri() == DCMAW_ASYNC) {

                    // Can attempt to complete a profile from here.

                    var dcmawContinuationResponse =
                            buildDCMAWContinuationResponse(
                                    credentialBundle,
                                    targetVot,
                                    clientOAuthSessionItem,
                                    auditEventUser,
                                    deviceInformation);

                    if (dcmawContinuationResponse != null) {
                        return dcmawContinuationResponse;
                    }
                }
            }

            // No relevant async CRI

            return buildNoMatchResponse(contraIndicators, targetVot);
        } catch (HttpResponseExceptionWithErrorBody
                | VerifiableCredentialException
                | EvcsServiceException e) {
            if (ErrorResponse.FAILED_NAME_CORRELATION.equals(e.getErrorResponse())) {
                return buildErrorResponse(e.getErrorResponse(), e, Level.INFO);
            }
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
        } catch (IpvSessionNotFoundException e) {
            return buildErrorResponse(ErrorResponse.IPV_SESSION_NOT_FOUND, e);
        } catch (CiExtractionException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_EXTRACT_CIS_FROM_VC, e);
        }
    }

    private VerifiableCredentialBundle getCredentialBundle(String userId, String evcsAccessToken)
            throws CredentialParseException, EvcsServiceException {
        var vcs =
                evcsService.getVerifiableCredentialsByState(
                        userId, evcsAccessToken, CURRENT, PENDING_RETURN);

        var isPendingReturn = !isNullOrEmpty(vcs.get(PENDING_RETURN));

        var evcsIdentityVcs = new ArrayList<VerifiableCredential>();
        if (isPendingReturn) {
            // + inherited VCs & pending VCs
            evcsIdentityVcs.addAll(
                    vcs.getOrDefault(CURRENT, List.of()).stream()
                            .filter(vc -> HMRC_MIGRATION.equals(vc.getCri()))
                            .toList());
            evcsIdentityVcs.addAll(vcs.getOrDefault(PENDING_RETURN, List.of()));
        } else {
            // + all vcs
            evcsIdentityVcs.addAll(vcs.getOrDefault(CURRENT, List.of()));
        }

        return new VerifiableCredentialBundle(evcsIdentityVcs, isPendingReturn);
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
                        VotHelper.getVotsByStrengthDescending(clientOAuthSessionItem),
                        credentialBundle.credentials,
                        contraIndicators,
                        areGpg45VcsCorrelated);

        if (maybeVotMatchingResult.isEmpty()) {
            return Optional.empty();
        }

        var votMatchingResult = maybeVotMatchingResult.get();

        if (GPG45.equals(votMatchingResult.vot().getProfileType())
                && !configService.enabled(PROCESS_CANDIDATE_IDENTITY)) {
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

        // If someone's ever picked up a CI, they can only try mitigation routes, even if it has
        // been mitigated.
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

    private JourneyResponse buildDCMAWContinuationResponse(
            VerifiableCredentialBundle credentialBundle,
            Vot lowestGpg45ConfidenceRequested,
            ClientOAuthSessionItem clientOAuthSessionItem,
            AuditEventUser auditEventUser,
            String deviceInformation)
            throws IpvSessionNotFoundException, VerifiableCredentialException {
        var criResponseItem =
                criResponseService.getCriResponseItem(
                        clientOAuthSessionItem.getUserId(), DCMAW_ASYNC);
        if (criResponseItem == null) {
            return null;
        }
        var criOAuthSessionItem =
                criOAuthSessionService.getCriOauthSessionItem(criResponseItem.getOauthState());
        if (criOAuthSessionItem == null) {
            return null;
        }
        var previousIpvSessionItem =
                ipvSessionService.getIpvSessionByClientOAuthSessionId(
                        criOAuthSessionItem.getClientOAuthSessionId());

        sendAuditEventWithPreviousIpvSessionId(
                AuditEventTypes.IPV_APP_SESSION_RECOVERED,
                auditEventUser,
                deviceInformation,
                previousIpvSessionItem.getIpvSessionId());

        sessionCredentialsService.persistCredentials(
                credentialBundle.credentials, auditEventUser.getSessionId(), false);

        return switch (lowestGpg45ConfidenceRequested) {
            case P1 -> JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW;
            case P2 -> JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM;
            default -> buildErrorResponse(ErrorResponse.INVALID_VTR_CLAIM);
        };
    }

    private JourneyResponse buildNoMatchResponse(
            List<ContraIndicator> contraIndicators, Vot preferredNewIdentityLevel)
            throws ConfigException, MitigationRouteException, HttpResponseExceptionWithErrorBody {

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

        return getNewIdentityJourney(preferredNewIdentityLevel);
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
                && allFraudVcsAreExpiredOrFromUnavailableSource(credentialBundle.credentials)) {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "All Fraud VCs are expired or from unavailable source"));
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

        return credentialBundle.isPendingReturn() ? JOURNEY_REUSE_WITH_STORE : JOURNEY_REUSE;
    }

    private JourneyResponse getNewIdentityJourney(Vot preferredNewIdentityLevel)
            throws HttpResponseExceptionWithErrorBody {
        switch (preferredNewIdentityLevel) {
            case P1 -> {
                LOGGER.info(LogHelper.buildLogMessage("New P1 IPV journey required"));
                return JOURNEY_IPV_GPG45_LOW;
            }
            case P2 -> {
                LOGGER.info(LogHelper.buildLogMessage("New P2 IPV journey required"));
                return JOURNEY_IPV_GPG45_MEDIUM;
            }
            default -> {
                LOGGER.info(LogHelper.buildLogMessage("Invalid preferredNewIdentityLevel"));
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatusCode.BAD_REQUEST, ErrorResponse.INVALID_VTR_CLAIM);
            }
        }
    }

    private List<VerifiableCredential> allVcsExceptFraud(List<VerifiableCredential> vcs) {
        return vcs.stream().filter(vc -> !EXPERIAN_FRAUD.equals(vc.getCri())).toList();
    }

    private boolean allFraudVcsAreExpiredOrFromUnavailableSource(List<VerifiableCredential> vcs) {
        return vcs.stream()
                .filter(vc -> vc.getCri() == EXPERIAN_FRAUD)
                .allMatch(
                        vc ->
                                VcHelper.isExpiredFraudVc(vc)
                                        || VcHelper.hasUnavailableFraudCheck(vc));
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

    private void sendAuditEventWithPreviousIpvSessionId(
            AuditEventTypes auditEventTypes,
            AuditEventUser auditEventUser,
            String deviceInformation,
            String previousIpvSessionId) {
        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        auditEventTypes,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditExtensionPreviousIpvSessionId(previousIpvSessionId),
                        new AuditRestrictedDeviceInformation(deviceInformation)));
    }

    private JourneyResponse buildErrorResponse(
            ErrorResponse errorResponse, Exception e, Level level) {
        LOGGER.log(level, LogHelper.buildErrorMessage(errorResponse.getMessage(), e));
        return new JourneyErrorResponse(
                JOURNEY_ERROR_PATH, HttpStatusCode.INTERNAL_SERVER_ERROR, errorResponse);
    }

    private JourneyResponse buildErrorResponse(ErrorResponse errorResponse, Exception e) {
        return buildErrorResponse(errorResponse, e, Level.ERROR);
    }

    private JourneyResponse buildErrorResponse(ErrorResponse errorResponse) {
        LOGGER.error(LogHelper.buildErrorMessage(errorResponse));
        return new JourneyErrorResponse(
                JOURNEY_ERROR_PATH, HttpStatusCode.INTERNAL_SERVER_ERROR, errorResponse);
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
            AsyncCriStatus f2fStatus, VerifiableCredentialBundle vcBundle) {
        // does the user have a F2F response item that was created in response to an intervention,
        // and they're returning to core with a pending identity
        return f2fStatus.cri() == F2F
                && f2fStatus.isReproveIdentity()
                && vcBundle.isPendingReturn();
    }
}
