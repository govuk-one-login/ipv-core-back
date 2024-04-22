package uk.gov.di.ipv.core.checkgpg45score;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownScoreTypeException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.SESSION_CREDENTIALS_TABLE_READS;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_SCORE_TYPE;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_MET_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_UNMET_PATH;

public class CheckGpg45ScoreHandler implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String FRAUD = "fraud";
    private static final String ACTIVITY = "activity";
    private static final String VERIFICATION = "verification";
    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final IpvSessionService ipvSessionService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final SessionCredentialsService sessionCredentialsService;

    @SuppressWarnings("unused") // Used by tests through injection
    public CheckGpg45ScoreHandler(
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            IpvSessionService ipvSessionService,
            UserIdentityService userIdentityService,
            VerifiableCredentialService verifiableCredentialService,
            SessionCredentialsService sessionCredentialsService) {
        this.configService = configService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.ipvSessionService = ipvSessionService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.sessionCredentialsService = sessionCredentialsService;
    }

    @SuppressWarnings("unused") // Used by AWS
    @ExcludeFromGeneratedCoverageReport
    public CheckGpg45ScoreHandler() {
        this.configService = new ConfigService();
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(ProcessRequest event, Context context) {
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
        } catch (CredentialParseException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Unable to parse GPG45 scores from existing credentials", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS)
                    .toObjectMap();
        } catch (UnknownEvidenceTypeException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unable to determine type of credential", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE)
                    .toObjectMap();
        } catch (UnknownScoreTypeException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unable to process score type", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.UNKNOWN_SCORE_TYPE)
                    .toObjectMap();
        }
    }

    private int getScore(String ipvSessionId, String scoreType)
            throws UnknownEvidenceTypeException, UnknownScoreTypeException,
                    CredentialParseException, VerifiableCredentialException {
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
            throws CredentialParseException, VerifiableCredentialException {
        IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
        ClientOAuthSessionItem clientOAuthSessionItem =
                clientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId());
        String userId = clientOAuthSessionItem.getUserId();
        LogHelper.attachGovukSigninJourneyIdToLogs(
                clientOAuthSessionItem.getGovukSigninJourneyId());
        return configService.enabled(SESSION_CREDENTIALS_TABLE_READS)
                ? sessionCredentialsService.getCredentials(ipvSessionId, userId)
                : verifiableCredentialService.getVcs(userId);
    }
}
