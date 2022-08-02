package uk.gov.di.ipv.core.issuedcredentials;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class IssuedCredentialsHandlerTest {

    @Mock private Context mockContext;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private IpvSessionService mockIpvSessionService;

    private final Gson gson = new Gson();

    @Test
    void shouldReturn200OnSuccessfulRequest() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String ipvSessionId = "a-session-id";
        String userId = "a-user-id";
        event.setHeaders(Map.of(RequestHelper.IPV_SESSION_ID_HEADER, ipvSessionId));

        when(mockIpvSessionService.getUserId(ipvSessionId)).thenReturn(userId);
        Map<String, String> userIssuedCredentials =
                Map.of(
                        "criOne", "credential issued by criOne",
                        "criTwo", "credential issued by criTwo",
                        "criThree", "credential issued by criThree");
        when(mockUserIdentityService.getUserIssuedDebugCredentials(userId))
                .thenReturn(userIssuedCredentials);
        IssuedCredentialsHandler issuedCredentialsHandler =
                new IssuedCredentialsHandler(
                        mockUserIdentityService, mockConfigurationService, mockIpvSessionService);

        APIGatewayProxyResponseEvent response =
                issuedCredentialsHandler.handleRequest(event, mockContext);

        assertEquals(200, response.getStatusCode());
        assertEquals(gson.toJson(userIssuedCredentials), response.getBody());
    }

    @Test
    void shouldReturn400IfNoSessionId() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        IssuedCredentialsHandler issuedCredentialsHandler =
                new IssuedCredentialsHandler(
                        mockUserIdentityService, mockConfigurationService, mockIpvSessionService);

        APIGatewayProxyResponseEvent response =
                issuedCredentialsHandler.handleRequest(event, mockContext);

        assertEquals(400, response.getStatusCode());
    }

    @Test
    void shouldReturn400IfSessionIdIsEmptyString() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(RequestHelper.IPV_SESSION_ID_HEADER, ""));
        IssuedCredentialsHandler issuedCredentialsHandler =
                new IssuedCredentialsHandler(
                        mockUserIdentityService, mockConfigurationService, mockIpvSessionService);

        APIGatewayProxyResponseEvent response =
                issuedCredentialsHandler.handleRequest(event, mockContext);

        assertEquals(400, response.getStatusCode());
    }
}
