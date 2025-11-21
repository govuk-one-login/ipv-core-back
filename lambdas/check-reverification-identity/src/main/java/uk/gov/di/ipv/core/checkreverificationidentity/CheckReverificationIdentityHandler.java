package uk.gov.di.ipv.core.checkreverificationidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.FlushMetrics;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatcher;

import java.io.UncheckedIOException;
import java.util.List;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_NOT_FOUND;
import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.domain.ReverificationFailureCode.NO_IDENTITY_AVAILABLE;
import static uk.gov.di.ipv.core.library.enums.Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FOUND;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NOT_FOUND_PATH;

public class CheckReverificationIdentityHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Map<String, Object> NOT_FOUND_RESPONSE =
            new JourneyResponse(JOURNEY_NOT_FOUND_PATH).toObjectMap();
    private static final Map<String, Object> FOUND_RESPONSE =
            new JourneyResponse(JOURNEY_FOUND).toObjectMap();
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientSessionService;
    private final EvcsService evcsService;
    private final UserIdentityService userIdentityService;
    private final VotMatcher votMatcher;

    public CheckReverificationIdentityHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            EvcsService evcsService,
            UserIdentityService userIdentityService,
            VotMatcher votMatcher) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientSessionService = clientOAuthSessionDetailsService;
        this.evcsService = evcsService;
        this.userIdentityService = userIdentityService;
        this.votMatcher = votMatcher;
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckReverificationIdentityHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckReverificationIdentityHandler(ConfigService configService) {
        this.configService = ConfigService.create();
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientSessionService = new ClientOAuthSessionDetailsService(configService);
        this.evcsService = new EvcsService(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.votMatcher =
                new VotMatcher(
                        userIdentityService,
                        new Gpg45ProfileEvaluator(),
                        new CimitUtilityService(configService));
    }

    @Override
    @Logging(clearState = true)
    @FlushMetrics(captureColdStart = true)
    public Map<String, Object> handleRequest(JourneyRequest request, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);
        configService.setFeatureSet(RequestHelper.getFeatureSet(request));

        try {
            var ipvSessionId = getIpvSessionId(request);
            LogHelper.attachIpvSessionIdToLogs(ipvSessionId);
            var ipvSession = ipvSessionService.getIpvSession(ipvSessionId);
            LogHelper.attachClientSessionIdToLogs(ipvSession.getClientOAuthSessionId());
            var clientOAuthSession =
                    clientSessionService.getClientOAuthSession(
                            ipvSession.getClientOAuthSessionId());
            LogHelper.attachClientIdToLogs(clientOAuthSession.getClientId());
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSession.getGovukSigninJourneyId());

            var vcs =
                    evcsService.getVerifiableCredentials(
                            clientOAuthSession.getUserId(),
                            clientOAuthSession.getEvcsAccessToken(),
                            CURRENT);

            if (!hasReverificationIdentity(vcs)) {
                ipvSession.setFailureCode(NO_IDENTITY_AVAILABLE);
                ipvSessionService.updateIpvSession(ipvSession);
                return NOT_FOUND_RESPONSE;
            }

            return FOUND_RESPONSE;

        } catch (HttpResponseExceptionWithErrorBody | EvcsServiceException e) {
            var errorMessage = LogHelper.buildErrorMessage(e.getErrorResponse());
            if (ErrorResponse.FAILED_NAME_CORRELATION.equals(e.getErrorResponse())) {
                LOGGER.info(errorMessage);
            } else {
                LOGGER.error(errorMessage);
            }
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (IpvSessionNotFoundException e) {
            LOGGER.error(LogHelper.buildErrorMessage("IPV session not found", e));
            return new JourneyErrorResponse(JOURNEY_ERROR_PATH, SC_NOT_FOUND, IPV_SESSION_NOT_FOUND)
                    .toObjectMap();
        } catch (CredentialParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to parse credentials", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            SC_SERVER_ERROR,
                            FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS)
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
        }
    }

    private boolean hasReverificationIdentity(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        var matchedVot =
                votMatcher.findStrongestMatches(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                        vcs,
                        List.of(),
                        userIdentityService.areVcsCorrelated(vcs));

        if (matchedVot.strongestRequestedMatch().isEmpty()) {
            LOGGER.info(LogHelper.buildLogMessage("No identity for reverification found"));
        }

        return matchedVot.strongestRequestedMatch().isPresent();
    }
}
