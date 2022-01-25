package uk.gov.di.ipv.core.sharedattributes;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.domain.SharedAttributes;
import uk.gov.di.ipv.core.library.domain.SharedAttributesResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class SharedAttributesHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(SharedAttributesHandler.class);

    public static final String IPV_SESSION_ID_HEADER_KEY = "ipv-session-id";
    public static final int BAD_REQUEST = 400;
    public static final int OK = 200;
    private final UserIdentityService userIdentityService;
    private final ObjectMapper mapper = new ObjectMapper();

    public SharedAttributesHandler(UserIdentityService userIdentityService) {
        this.userIdentityService = userIdentityService;
    }

    public SharedAttributesHandler() {
        this.userIdentityService = new UserIdentityService(new ConfigurationService());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            String ipvSessionId = getIpvSessionId(input.getHeaders());
            SharedAttributesResponse sharedAttributesResponse = getSharedAttributes(ipvSessionId);

            return ApiGatewayResponseGenerator.proxyJsonResponse(OK, sharedAttributesResponse);
        } catch (HttpResponseException e) {
            LOGGER.error(e.getMessage());
            return ApiGatewayResponseGenerator.proxyResponse(
                    e.getResponseCode(), e.getMessage(), Collections.EMPTY_MAP);
        }
    }

    private SharedAttributesResponse getSharedAttributes(String ipvSessionId)
            throws HttpResponseException {
        Map<String, String> credentials =
                userIdentityService.getUserIssuedCredentials(ipvSessionId);

        List<SharedAttributes> sharedAttributes = new ArrayList<>();
        for (String credential : credentials.values()) {
            try {
                sharedAttributes.add(mapper.readValue(credential, SharedAttributes.class));
            } catch (JsonProcessingException e) {
                throw new HttpResponseException(500, e.getMessage());
            }
        }
        return SharedAttributesResponse.from(sharedAttributes);
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
