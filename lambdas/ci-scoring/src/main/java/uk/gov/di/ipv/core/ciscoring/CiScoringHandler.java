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
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CiMitService;
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
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CiMitService ciMitService;
    private final ConfigService configService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final IpvSessionService ipvSessionService;

    @SuppressWarnings("unused") // Used by tests through injection
    public CiScoringHandler(
            CiMitService ciMitService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            ConfigService configService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            IpvSessionService ipvSessionService) {
        this.ciMitService = ciMitService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.configService = configService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.ipvSessionService = ipvSessionService;
    }

    @SuppressWarnings("unused") // Used by AWS
    @ExcludeFromGeneratedCoverageReport
    public CiScoringHandler() {
        this.configService = new ConfigService();
        this.ciMitService = new CiMitService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator(configService);
        this.ipvSessionService = new IpvSessionService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest event, Context context) {
        LogHelper.attachComponentIdToLogs();

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
                            ipAddress, clientOAuthSessionItem.getUserId(), govukSigninJourneyId);

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
            String ipAddress, String userId, String govukSigninJourneyId)
            throws ConfigException, UnrecognisedCiException, CiRetrievalException {
        return configService.enabled(CoreFeatureFlag.USE_CONTRA_INDICATOR_VC)
                ? gpg45ProfileEvaluator.getJourneyResponseForStoredContraIndicators(
                        ciMitService.getContraIndicatorsVC(userId, govukSigninJourneyId, ipAddress),
                        false)
                : gpg45ProfileEvaluator.getJourneyResponseForStoredCis(
                        ciMitService.getCIs(userId, govukSigninJourneyId, ipAddress));
    }
}
