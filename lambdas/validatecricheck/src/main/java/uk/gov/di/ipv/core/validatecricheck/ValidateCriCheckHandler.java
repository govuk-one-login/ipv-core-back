package uk.gov.di.ipv.core.validatecricheck;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.utils.StringUtils;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator;

import java.util.List;
import java.util.Map;

public class ValidateCriCheckHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    public static final String CRI_ID = "criId";
    public static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";
    public static final String JOURNEY_NEXT = "/journey/next";
    public static final String JOURNEY_FAIL = "/journey/fail";
    public static final String JOURNEY_ERROR = "/journey/error";

    private final CriCheckValidator criCheckValidator;
    private final UserIdentityService userIdentityService;
    private final IpvSessionService ipvSessionService;

    public ValidateCriCheckHandler(
            CriCheckValidator criCheckValidator,
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService) {
        this.criCheckValidator = criCheckValidator;
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ValidateCriCheckHandler() {
        this.criCheckValidator = new CriCheckValidator();
        ConfigurationService configurationService = new ConfigurationService();
        this.userIdentityService = new UserIdentityService(configurationService);
        this.ipvSessionService = new IpvSessionService(configurationService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(input);
            String userId = ipvSessionService.getUserId(ipvSessionId);
            String criId = getCriId(input.getPathParameters());
            LogHelper.attachCriIdToLogs(criId);

            JourneyResponse journeyResponse =
                    criCheckValidator.isSuccess(
                                    userIdentityService.getUserIssuedCredential(userId, criId))
                            ? new JourneyResponse(JOURNEY_NEXT)
                            : new JourneyResponse(JOURNEY_FAIL);

            LOGGER.info("VALIDATION RESULT: {}", journeyResponse.getJourney());

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, journeyResponse);
        } catch (HttpResponseExceptionWithErrorBody e) {
            if (List.of(
                            ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID,
                            ErrorResponse.MISSING_IPV_SESSION_ID)
                    .contains(e.getErrorResponse())) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        e.getResponseCode(), e.getErrorBody());
            }
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, new JourneyResponse(JOURNEY_ERROR));
        }
    }

    @Tracing
    private String getCriId(Map<String, String> pathParameters)
            throws HttpResponseExceptionWithErrorBody {
        if (pathParameters == null || StringUtils.isBlank(pathParameters.get(CRI_ID))) {
            LOGGER.error("Credential issuer ID path parameter missing");
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
        }
        return pathParameters.get(CRI_ID);
    }
}
