package uk.gov.di.ipv.core.evaluategpg45scores;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

public class EvaluateGpg45ScoresHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();
    public static final String JOURNEY_END = "/journey/end";
    public static final String JOURNEY_NEXT = "/journey/next";
    private final UserIdentityService userIdentityService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final CiStorageService ciStorageService;

    public EvaluateGpg45ScoresHandler(
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            CiStorageService ciStorageService) {
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.ciStorageService = ciStorageService;
    }

    public EvaluateGpg45ScoresHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.userIdentityService = new UserIdentityService(configurationService);
        this.ipvSessionService = new IpvSessionService(configurationService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
        this.ciStorageService = new CiStorageService(configurationService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent event, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(event);
            ClientSessionDetailsDto clientSessionDetailsDto =
                    ipvSessionService.getIpvSession(ipvSessionId).getClientSessionDetails();
            String userId = clientSessionDetailsDto.getUserId();

            String govukSigninJourneyId = clientSessionDetailsDto.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            List<ContraIndicatorItem> ciItems =
                    getCIsAndSwallowErrors(userId, govukSigninJourneyId);
            LOGGER.info("Retrieved {} CI items", ciItems.size());

            List<String> credentials = userIdentityService.getUserIssuedCredentials(userId);

            Optional<JourneyResponse> contraIndicatorErrorJourneyResponse =
                    gpg45ProfileEvaluator.contraIndicatorsPresent(credentials);
            if (contraIndicatorErrorJourneyResponse.isEmpty()) {
                boolean doCredentialsMeetM1BProfile =
                        gpg45ProfileEvaluator.credentialsSatisfyProfile(
                                credentials, Gpg45Profile.M1B);

                JourneyResponse journeyResponse;
                if (doCredentialsMeetM1BProfile) {
                    journeyResponse = new JourneyResponse(JOURNEY_END);
                } else {
                    journeyResponse =
                            gpg45ProfileEvaluator.credentialsSatisfyProfile(
                                            credentials, Gpg45Profile.M1A)
                                    ? new JourneyResponse(JOURNEY_END)
                                    : new JourneyResponse(JOURNEY_NEXT);
                }
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_OK, journeyResponse);
            } else {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_OK, contraIndicatorErrorJourneyResponse.get());
            }

        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        } catch (ParseException e) {
            LOGGER.error("Unable to parse GPG45 scores from existing credentials", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        } catch (UnknownEvidenceTypeException e) {
            LOGGER.error("Unable to determine type of credential", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE);
        }
    }

    @Tracing
    private List<ContraIndicatorItem> getCIsAndSwallowErrors(
            String userId, String govukSigninJourneyId) {
        try {
            return ciStorageService.getCIs(userId, govukSigninJourneyId);
        } catch (Exception e) {
            LOGGER.info("Exception thrown when calling CI storage system", e);
            return List.of();
        }
    }
}
