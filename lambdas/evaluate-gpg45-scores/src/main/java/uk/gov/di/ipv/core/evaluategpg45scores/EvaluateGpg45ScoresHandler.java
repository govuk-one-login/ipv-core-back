package uk.gov.di.ipv.core.evaluategpg45scores;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
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
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.journeys.JourneyUris;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.model.ContraIndicator;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_GPG45_PROFILE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JOURNEY_RESPONSE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_MET_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_UNMET_PATH;

/** Evaluate the gathered credentials against a desired GPG45 profile. */
public class EvaluateGpg45ScoresHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final JourneyResponse JOURNEY_MET = new JourneyResponse(JOURNEY_MET_PATH);
    private static final JourneyResponse JOURNEY_UNMET = new JourneyResponse(JOURNEY_UNMET_PATH);
    private static final JourneyResponse JOURNEY_VCS_NOT_CORRELATED =
            new JourneyResponse(JourneyUris.JOURNEY_VCS_NOT_CORRELATED);
    private static final Logger LOGGER = LogManager.getLogger();
    private final UserIdentityService userIdentityService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final ConfigService configService;
    private final AuditService auditService;
    private final CimitService cimitService;
    private final CimitUtilityService cimitUtilityService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final SessionCredentialsService sessionCredentialsService;

    @SuppressWarnings({
        "unused",
        "java:S107"
    }) // Used by tests through injection, methods should not have too many parameters
    public EvaluateGpg45ScoresHandler(
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            ConfigService configService,
            AuditService auditService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            SessionCredentialsService sessionCredentialsService,
            CimitService cimitService,
            CimitUtilityService cimitUtilityService) {
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.configService = configService;
        this.auditService = auditService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.cimitService = cimitService;
        this.cimitUtilityService = cimitUtilityService;
        VcHelper.setConfigService(this.configService);
    }

    @SuppressWarnings("unused") // Used by AWS
    @ExcludeFromGeneratedCoverageReport
    public EvaluateGpg45ScoresHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public EvaluateGpg45ScoresHandler(ConfigService configService) {
        this.configService = configService;
        this.userIdentityService = new UserIdentityService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
        this.auditService = AuditService.create(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.cimitService = new CimitService(configService);
        this.cimitUtilityService = new CimitUtilityService(configService);
        VcHelper.setConfigService(this.configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest event, Context context) {
        LogHelper.attachComponentId(configService);

        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(event);
            String ipAddress = RequestHelper.getIpAddress(event);
            configService.setFeatureSet(RequestHelper.getFeatureSet(event));
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            String userId = clientOAuthSessionItem.getUserId();

            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            var vcs = sessionCredentialsService.getCredentials(ipvSessionId, userId);

            if (!userIdentityService.areGpg45VcsCorrelated(vcs)) {
                return JOURNEY_VCS_NOT_CORRELATED.toObjectMap();
            }

            // This is a performance optimisation as calling cimitService.getContraIndicators()
            // takes about 0.5 seconds.
            // If the VTR only contains one entry then it is impossible for a user to reach here
            // with a breaching CI so we don't have to check.
            var contraIndicators =
                    clientOAuthSessionItem.getVtr().size() == 1
                            ? null
                            : cimitService.getContraIndicators(
                                    userId, govukSigninJourneyId, ipAddress);

            var matchingGpg45Profile =
                    findMatchingGpg45Profile(
                            vcs,
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            ipAddress,
                            event.getDeviceInformation(),
                            contraIndicators);

            if (matchingGpg45Profile.isEmpty()) {
                logLambdaResponse("No GPG45 profiles have been met", JOURNEY_UNMET);
                return JOURNEY_UNMET.toObjectMap();
            }

            ipvSessionItem.setVot(Vot.fromGpg45Profile(matchingGpg45Profile.get()));
            ipvSessionService.updateIpvSession(ipvSessionItem);

            logLambdaResponse("A GPG45 profile has been met", JOURNEY_MET);
            return JOURNEY_MET.toObjectMap();
        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Received exception", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (CiRetrievalException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            ErrorResponse.FAILED_TO_GET_STORED_CIS.getMessage(), e));
            return buildJourneyErrorResponse(ErrorResponse.FAILED_TO_GET_STORED_CIS);
        } catch (IpvSessionNotFoundException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to find ipv session", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, SC_INTERNAL_SERVER_ERROR, IPV_SESSION_NOT_FOUND)
                    .toObjectMap();
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        } finally {
            auditService.awaitAuditEvents();
        }
    }

    private Map<String, Object> buildJourneyErrorResponse(ErrorResponse errorResponse) {
        return new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH, HttpStatus.SC_INTERNAL_SERVER_ERROR, errorResponse)
                .toObjectMap();
    }

    private Optional<Gpg45Profile> findMatchingGpg45Profile(
            List<VerifiableCredential> vcs,
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String ipAddress,
            String deviceInformation,
            List<ContraIndicator> contraIndicators) {
        if (!userIdentityService.checkRequiresAdditionalEvidence(vcs)) {
            var gpg45Scores = gpg45ProfileEvaluator.buildScore(vcs);

            var requestedVotsByStrength =
                    clientOAuthSessionItem.getParsedVtr().getRequestedVotsByStrengthDescending();

            var gpg45Vots =
                    requestedVotsByStrength.stream()
                            .filter(vot -> vot.getSupportedGpg45Profiles() != null)
                            .toList();

            for (Vot requestedVot : gpg45Vots) {
                var profiles = requestedVot.getSupportedGpg45Profiles();

                var matchedProfile =
                        gpg45ProfileEvaluator.getFirstMatchingProfile(gpg45Scores, profiles);

                var isBreaching =
                        contraIndicators != null
                                && cimitUtilityService.isBreachingCiThreshold(
                                        contraIndicators, requestedVot);

                if (matchedProfile.isPresent() && !isBreaching) {
                    LOGGER.info(
                            LogHelper.buildLogMessage("GPG45 profile has been met.")
                                    .with(
                                            LOG_GPG45_PROFILE.getFieldName(),
                                            matchedProfile.get().getLabel()));
                    auditService.sendAuditEvent(
                            buildProfileMatchedAuditEvent(
                                    ipvSessionItem,
                                    clientOAuthSessionItem,
                                    matchedProfile.get(),
                                    gpg45Scores,
                                    vcs,
                                    ipAddress,
                                    deviceInformation));

                    return matchedProfile;
                }
            }
        }
        return Optional.empty();
    }

    private void logLambdaResponse(String lambdaResult, JourneyResponse journeyResponse) {
        var message =
                new StringMapMessage()
                        .with(LOG_LAMBDA_RESULT.getFieldName(), lambdaResult)
                        .with(LOG_JOURNEY_RESPONSE.getFieldName(), journeyResponse);
        LOGGER.info(message);
    }

    private AuditEvent buildProfileMatchedAuditEvent(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            Gpg45Profile gpg45Profile,
            Gpg45Scores gpg45Scores,
            List<VerifiableCredential> credentials,
            String ipAddress,
            String deviceInformation) {
        AuditEventUser auditEventUser =
                new AuditEventUser(
                        clientOAuthSessionItem.getUserId(),
                        ipvSessionItem.getIpvSessionId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        ipAddress);
        return AuditEvent.createWithDeviceInformation(
                AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                auditEventUser,
                new AuditExtensionGpg45ProfileMatched(
                        gpg45Profile,
                        gpg45Scores,
                        VcHelper.extractTxnIdsFromCredentials(credentials)),
                new AuditRestrictedDeviceInformation(deviceInformation));
    }
}
