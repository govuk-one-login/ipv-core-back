package uk.gov.di.ipv.core.checkexistingidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.library.ais.exception.AccountInterventionException;
import uk.gov.di.ipv.core.library.ais.helper.AccountInterventionEvaluator;
import uk.gov.di.ipv.core.library.ais.service.AisService;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionAccountIntervention;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionPreviousIpvSessionId;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.cricheckingservice.CriCheckingService;
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
import uk.gov.di.ipv.core.library.exceptions.MissingSecurityCheckCredential;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
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

import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_NOT_FOUND;
import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.AIS_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.REPEAT_FRAUD_CHECK;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.RESET_IDENTITY;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.STORED_IDENTITY_SERVICE;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ACCOUNT_INTERVENTION_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_DL_AUTH_SOURCE_CHECK_LOW_CONFIDENCE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_DL_AUTH_SOURCE_CHECK_MEDIUM_CONFIDENCE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_DL_AUTH_SOURCE_CHECK_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_NO_CI_LOW_CONFIDENCE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_NO_CI_MEDIUM_CONFIDENCE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_NO_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IPV_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IPV_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REPEAT_FRAUD_CHECK_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REUSE_WITH_STORE_PATH;

/** Check Existing Identity response Lambda */
public class CheckExistingIdentityHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final JourneyResponse JOURNEY_REUSE = new JourneyResponse(JOURNEY_REUSE_PATH);
    private static final JourneyResponse JOURNEY_REUSE_WITH_STORE =
            new JourneyResponse(JOURNEY_REUSE_WITH_STORE_PATH);
    private static final JourneyResponse JOURNEY_IPV_GPG45_LOW =
            new JourneyResponse(JOURNEY_IPV_GPG45_LOW_PATH);
    private static final JourneyResponse JOURNEY_IPV_GPG45_MEDIUM =
            new JourneyResponse(JOURNEY_IPV_GPG45_MEDIUM_PATH);
    private static final JourneyResponse JOURNEY_F2F_FAIL =
            new JourneyResponse(JOURNEY_F2F_FAIL_PATH);
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
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH);
    private static final JourneyResponse JOURNEY_FAIL_WITH_NO_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_NO_CI_PATH);
    private static final JourneyResponse JOURNEY_FAIL_WITH_NO_CI_LOW_CONFIDENCE =
            new JourneyResponse(JOURNEY_FAIL_WITH_NO_CI_LOW_CONFIDENCE_PATH);
    private static final JourneyResponse JOURNEY_FAIL_WITH_NO_CI_MEDIUM_CONFIDENCE =
            new JourneyResponse(JOURNEY_FAIL_WITH_NO_CI_MEDIUM_CONFIDENCE_PATH);
    private static final JourneyResponse JOURNEY_DL_AUTH_SOURCE_CHECK =
            new JourneyResponse(JOURNEY_DL_AUTH_SOURCE_CHECK_PATH);
    private static final JourneyResponse JOURNEY_DL_AUTH_SOURCE_CHECK_LOW_CONFIDENCE =
            new JourneyResponse(JOURNEY_DL_AUTH_SOURCE_CHECK_LOW_CONFIDENCE_PATH);
    private static final JourneyResponse JOURNEY_DL_AUTH_SOURCE_CHECK_MEDIUM_CONFIDENCE =
            new JourneyResponse(JOURNEY_DL_AUTH_SOURCE_CHECK_MEDIUM_CONFIDENCE_PATH);
    private static final JourneyResponse JOURNEY_ACCOUNT_INTERVENTION =
            new JourneyResponse(JOURNEY_ACCOUNT_INTERVENTION_PATH);

    private static final String ACCOUNT_INTERVENTION_ERROR_DESCRIPTION =
            "Account intervention detected";

    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final CriCheckingService criCheckingService;
    private final CriResponseService criResponseService;
    private final CriOAuthSessionService criOAuthSessionService;
    private final IpvSessionService ipvSessionService;
    private final AuditService auditService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CimitService cimitService;
    private final CimitUtilityService cimitUtilityService;
    private final SessionCredentialsService sessionCredentialsService;
    private final EvcsService evcsService;
    private final AisService aisService;
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
            CriCheckingService criCheckingService,
            CriResponseService criResponseService,
            CimitService cimitService,
            CimitUtilityService cimitUtilityService,
            SessionCredentialsService sessionCredentialsService,
            CriOAuthSessionService criOAuthSessionService,
            EvcsService evcsService,
            AisService aisService,
            VotMatcher votMatcher) {
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.auditService = auditService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criCheckingService = criCheckingService;
        this.criResponseService = criResponseService;
        this.cimitService = cimitService;
        this.cimitUtilityService = cimitUtilityService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.evcsService = evcsService;
        this.criOAuthSessionService = criOAuthSessionService;
        this.votMatcher = votMatcher;
        this.aisService = aisService;
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
        this.criCheckingService =
                new CriCheckingService(
                        configService,
                        auditService,
                        userIdentityService,
                        cimitService,
                        cimitUtilityService,
                        ipvSessionService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.evcsService = new EvcsService(configService);
        this.criOAuthSessionService = new CriOAuthSessionService(configService);
        this.aisService = new AisService(configService);
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
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);

        try {
            var ipvSessionId = getIpvSessionId(event);
            var ipAddress = getIpAddress(event);
            var deviceInformation = event.getDeviceInformation();
            configService.setFeatureSet(RequestHelper.getFeatureSet(event));

            var ipvSessionItem = ipvSessionService.getIpvSessionWithRetry(ipvSessionId);
            var clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            var userId = clientOAuthSessionItem.getUserId();
            var govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            var isReproveIdentity =
                    Boolean.TRUE.equals(clientOAuthSessionItem.getReproveIdentity());

            if (configService.enabled(AIS_ENABLED)) {
                var accountInterventionStateWithType = aisService.fetchAccountStateWithType(userId);
                var fetchedAccountInterventionState =
                        accountInterventionStateWithType.accountInterventionState();
                var fetchedAisInterventionType =
                        accountInterventionStateWithType.aisInterventionType();

                ipvSessionItem.setInitialAccountInterventionState(fetchedAccountInterventionState);
                ipvSessionItem.setAisInterventionType(fetchedAisInterventionType);
                isReproveIdentity = fetchedAccountInterventionState.isReproveIdentity();

                if (AccountInterventionEvaluator.hasInvalidAccountIntervention(
                        fetchedAisInterventionType)) {
                    ipvSessionService.invalidateSession(
                            ipvSessionItem, ACCOUNT_INTERVENTION_ERROR_DESCRIPTION);
                    throw new AccountInterventionException();
                }

                clientOAuthSessionItem.setReproveIdentity(isReproveIdentity);
                clientOAuthSessionDetailsService.updateClientSessionDetails(clientOAuthSessionItem);
            }

            ipvSessionService.updateIpvSession(ipvSessionItem);

            var auditEventUser =
                    new AuditEventUser(userId, ipvSessionId, govukSigninJourneyId, ipAddress);

            if (isReproveIdentity) {
                auditService.sendAuditEvent(
                        AuditEvent.createWithoutDeviceInformation(
                                AuditEventTypes.IPV_ACCOUNT_INTERVENTION_START,
                                configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                                auditEventUser,
                                AuditExtensionAccountIntervention.newReproveIdentity()));
            }

            if (configService.enabled(STORED_IDENTITY_SERVICE)) {
                evcsService.invalidateStoredIdentityRecord(clientOAuthSessionItem.getUserId());
            }

            return getJourneyResponse(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            ipAddress,
                            deviceInformation,
                            userId,
                            govukSigninJourneyId,
                            auditEventUser)
                    .toObjectMap();
        } catch (AccountInterventionException e) {
            return JOURNEY_ACCOUNT_INTERVENTION.toObjectMap();
        } catch (HttpResponseExceptionWithErrorBody | EvcsServiceException e) {
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (IpvSessionNotFoundException e) {
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, SC_NOT_FOUND, ErrorResponse.IPV_SESSION_NOT_FOUND)
                    .toObjectMap();
        } catch (UncheckedIOException e) {
            // Temporary mitigation to force lambda instance to crash and restart by explicitly
            // exiting the program on fatal IOException - see PYIC-8220 and incident INC0014398.
            LOGGER.error("Crashing on UncheckedIOException", e);
            System.exit(1);
            return null;
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
            String deviceInformation,
            String userId,
            String govukSigninJourneyId,
            AuditEventUser auditEventUser) {
        try {
            var evcsAccessToken = clientOAuthSessionItem.getEvcsAccessToken();
            var credentialBundle = getCredentialBundle(userId, evcsAccessToken);

            var asyncCriStatus =
                    criResponseService.getAsyncResponseStatus(
                            userId, credentialBundle.credentials, credentialBundle.isPendingReturn);

            var targetVot = VotHelper.getThresholdVot(ipvSessionItem, clientOAuthSessionItem);

            var contraIndicatorsVc =
                    cimitService.fetchContraIndicatorsVc(
                            clientOAuthSessionItem.getUserId(),
                            govukSigninJourneyId,
                            ipAddress,
                            ipvSessionItem);

            var contraIndicators =
                    cimitUtilityService.getContraIndicatorsFromVc(contraIndicatorsVc);

            var isReproveIdentity = clientOAuthSessionItem.getReproveIdentity();

            // Only skip starting a new reprove identity journey if the user is returning from a F2F
            // journey
            if (Boolean.TRUE.equals(isReproveIdentity)
                            && !isReprovingWithF2f(asyncCriStatus, credentialBundle)
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
            if (cimitUtilityService.isBreachingCiThreshold(contraIndicators, targetVot)
                    && cimitUtilityService
                            .getCiMitigationEvent(contraIndicators, targetVot)
                            .isEmpty()) {
                return JOURNEY_FAIL_WITH_CI;
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

            // No profile matched, are we waiting for an async VC?
            if (asyncCriStatus.isAwaitingVc()) {
                return asyncCriStatus.getJourneyForAwaitingVc(false);
            }

            // No awaited async vc, do we already have an async VC.
            if (asyncCriStatus.isPendingReturn()) {
                if (asyncCriStatus.cri() == F2F) {

                    // Returned with F2F async VC. Should have matched a profile.
                    return buildF2FNoMatchResponse(
                            areGpg45VcsCorrelated, auditEventUser, deviceInformation);
                }
                if (asyncCriStatus.cri() == DCMAW_ASYNC) {

                    // Can attempt to complete a profile from here.
                    var dcmawContinuationResponse =
                            buildDCMAWContinuationResponse(
                                    credentialBundle,
                                    ipAddress,
                                    ipvSessionItem,
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
            return getNewIdentityJourney(targetVot);
        } catch (HttpResponseExceptionWithErrorBody
                | VerifiableCredentialException
                | EvcsServiceException e) {
            if (ErrorResponse.FAILED_NAME_CORRELATION.equals(e.getErrorResponse())) {
                return buildErrorResponse(e.getErrorResponse(), e, Level.INFO);
            }
            return buildErrorResponse(e.getErrorResponse(), e);
        } catch (CiRetrievalException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_GET_STORED_CIS, e);
        } catch (CredentialParseException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS, e);
        } catch (ConfigException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_PARSE_CONFIG, e);
        } catch (UnrecognisedCiException e) {
            return buildErrorResponse(ErrorResponse.UNRECOGNISED_CI_CODE, e);
        } catch (IpvSessionNotFoundException e) {
            return buildErrorResponse(ErrorResponse.IPV_SESSION_NOT_FOUND, e);
        } catch (CiExtractionException e) {
            return buildErrorResponse(ErrorResponse.FAILED_TO_EXTRACT_CIS_FROM_VC, e);
        } catch (MissingSecurityCheckCredential e) {
            return buildErrorResponse(ErrorResponse.MISSING_SECURITY_CHECK_CREDENTIAL, e);
        }
    }

    private VerifiableCredentialBundle getCredentialBundle(String userId, String evcsAccessToken)
            throws CredentialParseException, EvcsServiceException {
        var vcs =
                evcsService.fetchEvcsVerifiableCredentialsByState(
                        userId, evcsAccessToken, CURRENT, PENDING_RETURN);

        // PENDING_RETURN vcs need a pending record to be valid
        var pendingRecords = criResponseService.getCriResponseItems(userId);
        var pendingReturnVcs = vcs.getOrDefault(PENDING_RETURN, List.of());
        var hasValidPendingReturnVcs =
                !pendingRecords.isEmpty() && !isNullOrEmpty(pendingReturnVcs);

        var evcsIdentityVcs = new ArrayList<VerifiableCredential>();
        if (hasValidPendingReturnVcs) {
            // + pending return VCs
            evcsIdentityVcs.addAll(pendingReturnVcs);
        } else {
            // + all vcs
            evcsIdentityVcs.addAll(vcs.getOrDefault(CURRENT, List.of()));
        }

        return new VerifiableCredentialBundle(evcsIdentityVcs, hasValidPendingReturnVcs);
    }

    private Optional<JourneyResponse> checkForProfileMatch(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            AuditEventUser auditEventUser,
            String deviceInformation,
            VerifiableCredentialBundle credentialBundle,
            boolean areGpg45VcsCorrelated,
            List<ContraIndicator> contraIndicators)
            throws VerifiableCredentialException {
        // Check for attained vot from requested vots
        var votMatchingResult =
                votMatcher.findStrongestMatches(
                        clientOAuthSessionItem.getVtrAsVots(),
                        credentialBundle.credentials,
                        contraIndicators,
                        areGpg45VcsCorrelated);

        var strongestRequestedMatch = votMatchingResult.strongestRequestedMatch();

        if (strongestRequestedMatch.isEmpty()) {
            return Optional.empty();
        }

        var requestedMatch = strongestRequestedMatch.get();

        // vot achieved for vtr
        return Optional.of(
                buildReuseResponse(
                        requestedMatch.vot(),
                        ipvSessionItem,
                        credentialBundle,
                        auditEventUser,
                        deviceInformation));
    }

    private JourneyResponse buildF2FNoMatchResponse(
            boolean areGpg45VcsCorrelated,
            AuditEventUser auditEventUser,
            String deviceInformation) {
        LOGGER.info(LogHelper.buildLogMessage("F2F return - failed to match a profile."));
        sendAuditEvent(
                !areGpg45VcsCorrelated
                        ? AuditEventTypes.IPV_F2F_CORRELATION_FAIL
                        : AuditEventTypes.IPV_F2F_PROFILE_NOT_MET_FAIL,
                auditEventUser,
                deviceInformation);

        return JOURNEY_F2F_FAIL;
    }

    private JourneyResponse buildDCMAWContinuationResponse(
            VerifiableCredentialBundle credentialBundle,
            String ipAddress,
            IpvSessionItem ipvSessionItem,
            Vot lowestGpg45ConfidenceRequested,
            ClientOAuthSessionItem clientOAuthSessionItem,
            AuditEventUser auditEventUser,
            String deviceInformation)
            throws IpvSessionNotFoundException,
                    VerifiableCredentialException,
                    CiExtractionException,
                    HttpResponseExceptionWithErrorBody,
                    CredentialParseException,
                    ConfigException,
                    CiRetrievalException,
                    MissingSecurityCheckCredential {
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
                credentialBundle.credentials, auditEventUser.getSessionId(), true);

        var forcedJourney =
                criCheckingService.checkVcResponse(
                        credentialBundle.credentials,
                        ipAddress,
                        clientOAuthSessionItem,
                        ipvSessionItem,
                        credentialBundle.credentials);
        if (forcedJourney != null) {
            if (JOURNEY_FAIL_WITH_NO_CI.equals(forcedJourney)) {
                return switch (lowestGpg45ConfidenceRequested) {
                    case P1 -> JOURNEY_FAIL_WITH_NO_CI_LOW_CONFIDENCE;
                    case P2 -> JOURNEY_FAIL_WITH_NO_CI_MEDIUM_CONFIDENCE;
                    default -> buildErrorResponse(ErrorResponse.INVALID_VTR_CLAIM);
                };
            }
            if (JOURNEY_DL_AUTH_SOURCE_CHECK.equals(forcedJourney)) {
                return switch (lowestGpg45ConfidenceRequested) {
                    case P1 -> JOURNEY_DL_AUTH_SOURCE_CHECK_LOW_CONFIDENCE;
                    case P2 -> JOURNEY_DL_AUTH_SOURCE_CHECK_MEDIUM_CONFIDENCE;
                    default -> buildErrorResponse(ErrorResponse.INVALID_VTR_CLAIM);
                };
            }
            return forcedJourney;
        }

        return switch (lowestGpg45ConfidenceRequested) {
            case P1 -> JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW;
            case P2 -> JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM;
            default -> buildErrorResponse(ErrorResponse.INVALID_VTR_CLAIM);
        };
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

        sessionCredentialsService.persistCredentials(
                credentialBundle.credentials, auditEventUser.getSessionId(), false);

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

    private boolean isReprovingWithF2f(
            AsyncCriStatus f2fStatus, VerifiableCredentialBundle vcBundle) {
        // does the user have a F2F response item that was created in response to an intervention,
        // and they're returning to core with a pending identity
        return f2fStatus.cri() == F2F
                && f2fStatus.isReproveIdentity()
                && vcBundle.isPendingReturn();
    }
}
