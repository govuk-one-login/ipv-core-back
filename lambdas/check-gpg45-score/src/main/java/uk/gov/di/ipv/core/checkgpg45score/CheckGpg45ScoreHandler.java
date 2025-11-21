package uk.gov.di.ipv.core.checkgpg45score;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.FlushMetrics;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.ClientOauthSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownScoreTypeException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.io.UncheckedIOException;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_SCORE_TYPE;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_MET_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_UNMET_PATH;

public class CheckGpg45ScoreHandler implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String FRAUD = "fraud";
    private static final String ACTIVITY = "activity";
    private static final String VERIFICATION = "verification";
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final IpvSessionService ipvSessionService;
    private final SessionCredentialsService sessionCredentialsService;

    @SuppressWarnings("unused") // Used by tests through injection
    public CheckGpg45ScoreHandler(
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            IpvSessionService ipvSessionService,
            UserIdentityService userIdentityService,
            SessionCredentialsService sessionCredentialsService) {
        this.configService = configService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.ipvSessionService = ipvSessionService;
        this.sessionCredentialsService = sessionCredentialsService;
    }

    @SuppressWarnings("unused") // Used by AWS
    @ExcludeFromGeneratedCoverageReport
    public CheckGpg45ScoreHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckGpg45ScoreHandler(ConfigService configService) {
        this.configService = configService;
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
        this.sessionCredentialsService = new SessionCredentialsService(configService);
    }

    @Override
    @Logging(clearState = true)
    @FlushMetrics(captureColdStart = true)
    public Map<String, Object> handleRequest(ProcessRequest event, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);

        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(event);
            String scoreType = RequestHelper.getScoreType(event);
            Integer scoreThreshold = RequestHelper.getScoreThreshold(event);
            configService.setFeatureSet(RequestHelper.getFeatureSet(event));

            int scoreToCompare = getScore(ipvSessionId, scoreType);
            if (scoreToCompare >= scoreThreshold) {
                LOGGER.info(
                        new StringMapMessage()
                                .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "Score threshold met")
                                .with(LOG_SCORE_TYPE.getFieldName(), scoreType));
                return new JourneyResponse(JOURNEY_MET_PATH).toObjectMap();
            } else {
                LOGGER.info(
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "Score threshold not met")
                                .with(LOG_SCORE_TYPE.getFieldName(), scoreType));
                return new JourneyResponse(JOURNEY_UNMET_PATH).toObjectMap();
            }
        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Received exception", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (UnknownScoreTypeException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unable to process score type", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                            ErrorResponse.UNKNOWN_SCORE_TYPE)
                    .toObjectMap();
        } catch (IpvSessionNotFoundException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to find ipv session", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                            IPV_SESSION_NOT_FOUND)
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

    private int getScore(String ipvSessionId, String scoreType)
            throws UnknownScoreTypeException,
                    VerifiableCredentialException,
                    IpvSessionNotFoundException,
                    ClientOauthSessionNotFoundException {
        var vcs = getParsedCredentials(ipvSessionId);
        var gpg45Scores = gpg45ProfileEvaluator.buildScore(vcs);
        return switch (scoreType) {
            case FRAUD -> gpg45Scores.getFraud();
            case ACTIVITY -> gpg45Scores.getActivity();
            case VERIFICATION -> gpg45Scores.getVerification();
            default -> throw new UnknownScoreTypeException("Invalid score type: " + scoreType);
        };
    }

    private List<VerifiableCredential> getParsedCredentials(String ipvSessionId)
            throws VerifiableCredentialException,
                    IpvSessionNotFoundException,
                    ClientOauthSessionNotFoundException {
        IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
        ClientOAuthSessionItem clientOAuthSessionItem =
                clientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId());
        String userId = clientOAuthSessionItem.getUserId();
        LogHelper.attachGovukSigninJourneyIdToLogs(
                clientOAuthSessionItem.getGovukSigninJourneyId());
        return sessionCredentialsService.getCredentials(ipvSessionId, userId);
    }
}
