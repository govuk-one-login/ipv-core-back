package uk.gov.di.ipv.core.ciscoring;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cimit.CiMitService;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.cimit.CimitEvaluator;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_JOURNEY_RESPONSE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NEXT_PATH;

public class CiScoringHandler implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String USER_STATE_INITIAL_CI_SCORING = "INITIAL_CI_SCORING";
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CiMitService ciMitService;
    private final ConfigService configService;
    private final CimitEvaluator cimitEvaluator;
    private final IpvSessionService ipvSessionService;

    @SuppressWarnings("unused") // Used by tests through injection
    public CiScoringHandler(
            CiMitService ciMitService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            ConfigService configService,
            IpvSessionService ipvSessionService,
            CimitEvaluator cimitEvaluator) {
        this.ciMitService = ciMitService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.cimitEvaluator = cimitEvaluator;
    }

    @SuppressWarnings("unused") // Used by AWS
    @ExcludeFromGeneratedCoverageReport
    public CiScoringHandler() {
        this.configService = new ConfigService();
        this.ciMitService = new CiMitService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.cimitEvaluator = new CimitEvaluator(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest event, Context context) {
        LogHelper.attachComponentIdToLogs(configService);

        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(event);
            String ipAddress = RequestHelper.getIpAddress(event);
            String featureSet = RequestHelper.getFeatureSet(event);
            configService.setFeatureSet(featureSet);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());

            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            final Optional<JourneyResponse> contraIndicatorErrorJourneyResponse =
                    getContraIndicatorJourneyResponse(
                            USER_STATE_INITIAL_CI_SCORING.equals(ipvSessionItem.getUserState()),
                            ipAddress,
                            clientOAuthSessionItem.getUserId(),
                            govukSigninJourneyId);

            if (contraIndicatorErrorJourneyResponse.isPresent()) {
                StringMapMessage message = new StringMapMessage();
                message.with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "Returning CI error response.")
                        .with(
                                LOG_ERROR_JOURNEY_RESPONSE.getFieldName(),
                                contraIndicatorErrorJourneyResponse.get().toString());
                LOGGER.info(message);
                return contraIndicatorErrorJourneyResponse.get().toObjectMap();
            }

            return JOURNEY_NEXT.toObjectMap();
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error("Received HTTP response exception", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (CiRetrievalException e) {
            LOGGER.error("Error when fetching CIs from storage system", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_GET_STORED_CIS)
                    .toObjectMap();
        } catch (ConfigException e) {
            LOGGER.error("Configuration error", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_PARSE_CONFIG)
                    .toObjectMap();
        } catch (UnrecognisedCiException e) {
            LOGGER.error("Unrecognised CI code received", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.UNRECOGNISED_CI_CODE)
                    .toObjectMap();
        }
    }

    private Optional<JourneyResponse> getContraIndicatorJourneyResponse(
            boolean initialCiScoring, String ipAddress, String userId, String govukSigninJourneyId)
            throws ConfigException, UnrecognisedCiException, CiRetrievalException {
        return configService.enabled(CoreFeatureFlag.USE_CONTRA_INDICATOR_VC)
                ? cimitEvaluator.getJourneyResponseForStoredContraIndicators(
                        ciMitService.getContraIndicatorsVC(userId, govukSigninJourneyId, ipAddress),
                        initialCiScoring)
                : cimitEvaluator.getJourneyResponseForStoredCis(
                        ciMitService.getCIs(userId, govukSigninJourneyId, ipAddress));
    }
}
