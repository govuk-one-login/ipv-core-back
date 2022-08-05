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
import uk.gov.di.ipv.core.evaluategpg45scores.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.evaluategpg45scores.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.evaluategpg45scores.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.text.ParseException;
import java.util.List;

public class EvaluateGpg45ScoresHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();
    public static final String JOURNEY_SESSION_END = "/journey/session/end";
    public static final String JOURNEY_NEXT = "/journey/next";
    public static final String JOURNEY_ERROR = "/journey/error";
    public static final String JOURNEY_FAIL = "/journey/fail";
    private final UserIdentityService userIdentityService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;

    public EvaluateGpg45ScoresHandler(
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator) {
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
    }

    public EvaluateGpg45ScoresHandler() {
        ConfigurationService configurationService = new ConfigurationService();
        this.userIdentityService = new UserIdentityService(configurationService);
        this.ipvSessionService = new IpvSessionService(configurationService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
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

            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientSessionDetailsDto.getGovukSigninJourneyId());

            List<String> credentials = userIdentityService.getUserIssuedCredentials(userId);

            JourneyResponse journeyResponse;
            if (gpg45ProfileEvaluator.anyCredentialsGatheredDoNotMeetM1A(credentials)) {
                // This will eventually be handled by the CRI select lambda. We are only
                // failing the journey here for temporary convenience. This lambda should
                // only have responsibility for ending the journey if we have met a profile.
                journeyResponse = new JourneyResponse(JOURNEY_FAIL);
            } else {
                journeyResponse =
                        gpg45ProfileEvaluator.credentialsSatisfyProfile(
                                        credentials, Gpg45Profile.M1A)
                                ? new JourneyResponse(JOURNEY_SESSION_END)
                                : new JourneyResponse(JOURNEY_NEXT);
            }

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, journeyResponse);
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        } catch (ParseException e) {
            LOGGER.error("Unable to parse GPG45 scores from existing credentials", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, new JourneyResponse(JOURNEY_ERROR));
        } catch (UnknownEvidenceTypeException e) {
            LOGGER.error("Unable to determine type of credential", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, new JourneyResponse(JOURNEY_ERROR));
        }
    }
}
