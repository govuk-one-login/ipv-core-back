package uk.gov.di.ipv.core.validatecricheck;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.utils.StringUtils;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator;

import java.util.Map;

public class ValidateCriCheckHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ValidateCriCheckHandler.class);
    public static final String CRI_ID = "criId";
    public static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";
    public static final String JOURNEY_NEXT = "/journey/next";
    public static final String JOURNEY_FAIL = "/journey/fail";
    public static final int OK = 200;
    public static final int BAD_REQUEST = 400;

    private final CriCheckValidator criCheckValidator;
    private final UserIdentityService userIdentityService;

    public ValidateCriCheckHandler(
            CriCheckValidator criCheckValidator, UserIdentityService userIdentityService) {
        this.criCheckValidator = criCheckValidator;
        this.userIdentityService = userIdentityService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ValidateCriCheckHandler() {
        this.criCheckValidator = new CriCheckValidator();
        this.userIdentityService = new UserIdentityService(new ConfigurationService());
    }

    @Override
    @Tracing
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        try {
            String criId = getCriId(input.getPathParameters());
            String ipvSessionId = getIpvSessionId(input.getHeaders());

            JourneyResponse journeyResponse =
                    criCheckValidator.isSuccess(
                                    userIdentityService.getUserIssuedCredential(
                                            ipvSessionId, criId))
                            ? new JourneyResponse(JOURNEY_NEXT)
                            : new JourneyResponse(JOURNEY_FAIL);
            return ApiGatewayResponseGenerator.proxyJsonResponse(OK, journeyResponse);
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        }
    }

    @Tracing
    private String getCriId(Map<String, String> pathParameters)
            throws HttpResponseExceptionWithErrorBody {
        if (pathParameters == null || StringUtils.isBlank(pathParameters.get(CRI_ID))) {
            LOGGER.error("Credential issuer ID path parameter missing");
            throw new HttpResponseExceptionWithErrorBody(
                    BAD_REQUEST, ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
        }
        return pathParameters.get(CRI_ID);
    }

    @Tracing
    private String getIpvSessionId(Map<String, String> headers)
            throws HttpResponseExceptionWithErrorBody {
        String ipvSessionId = RequestHelper.getHeaderByKey(headers, IPV_SESSION_ID_HEADER_KEY);
        if (ipvSessionId == null) {
            LOGGER.error("{} not present in header", IPV_SESSION_ID_HEADER_KEY);
            throw new HttpResponseExceptionWithErrorBody(
                    BAD_REQUEST, ErrorResponse.MISSING_IPV_SESSION_ID);
        }
        return ipvSessionId;
    }
}
