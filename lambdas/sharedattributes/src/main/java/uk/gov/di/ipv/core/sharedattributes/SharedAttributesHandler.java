package uk.gov.di.ipv.core.sharedattributes;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;

import java.util.Collections;
import java.util.Map;

public class SharedAttributesHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(SharedAttributesHandler.class);

    public static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";
    public static final int BAD_REQUEST = 400;
    public static final int OK = 200;

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            String ipvSessionId = getIpvSessionId(input.getHeaders());
            return ApiGatewayResponseGenerator.proxyJsonResponse(OK, "");
        } catch (HttpResponseException e) {
            LOGGER.error(e.getMessage());
            return ApiGatewayResponseGenerator.proxyResponse(
                    e.getResponseCode(), e.getMessage(), Collections.EMPTY_MAP);
        }
    }

    private String getIpvSessionId(Map<String, String> headers) throws HttpResponseException {
        String ipvSessionId = RequestHelper.getHeaderByKey(headers, IPV_SESSION_ID_HEADER_KEY);
        if (ipvSessionId == null) {
            throw new HttpResponseException(
                    BAD_REQUEST,
                    String.format("%s not present in header", IPV_SESSION_ID_HEADER_KEY));
        }
        return ipvSessionId;
    }
}
