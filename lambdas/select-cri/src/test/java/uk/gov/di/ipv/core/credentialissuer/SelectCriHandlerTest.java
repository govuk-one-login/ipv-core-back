package uk.gov.di.ipv.core.credentialissuer;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.selectcri.SelectCriHandler;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ADDRESS_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PASSPORT_CRI_ID;

@ExtendWith(MockitoExtension.class)
class SelectCriHandlerTest {

    public static final String TEST_SESSION_ID = "the-session-id";
    public static final String TEST_USER_ID = "test-user-id";
    public static final String CRI_PASSPORT = "ukPassport";
    public static final String CRI_FRAUD = "fraudCri";
    public static final String CRI_KBV = "kbv";
    public static final String CRI_ADDRESS = "address";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock private Context context;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @Mock private ClientSessionDetailsDto mockClientSessionDetailsDto;
    @InjectMocks private SelectCriHandler underTest;

    @Test
    void shouldReturnPassportCriJourneyResponse() throws JsonProcessingException {
        mockIpvSessionService();
        when(mockUserIdentityService.getUserIssuedCredentialIssuers(TEST_USER_ID))
                .thenReturn(Collections.emptyList());

        mockConfigurationServiceMethodCalls();

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/ukPassport", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    private void mockIpvSessionService() {
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(mockClientSessionDetailsDto);
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionService.getUserId(TEST_SESSION_ID)).thenReturn(TEST_USER_ID);
    }

    @Test
    void shouldReturnAddressCriJourneyResponse() throws JsonProcessingException {
        mockIpvSessionService();
        when(mockUserIdentityService.getUserIssuedCredentialIssuers(TEST_USER_ID))
                .thenReturn(List.of(CRI_PASSPORT));

        mockConfigurationServiceMethodCalls();

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/address", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnFraudCriJourneyResponse() throws JsonProcessingException {
        mockIpvSessionService();
        when(mockUserIdentityService.getUserIssuedCredentialIssuers(TEST_USER_ID))
                .thenReturn(List.of(CRI_PASSPORT, CRI_ADDRESS));

        mockConfigurationServiceMethodCalls();

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/fraudCri", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnKBVCriJourneyResponse() throws JsonProcessingException {
        mockIpvSessionService();
        when(mockUserIdentityService.getUserIssuedCredentialIssuers(TEST_USER_ID))
                .thenReturn(List.of(CRI_PASSPORT, CRI_ADDRESS, CRI_FRAUD));

        mockConfigurationServiceMethodCalls();

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/kbv", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnJourneyFailedIfAllCriVisited() throws JsonProcessingException {
        mockIpvSessionService();
        when(mockUserIdentityService.getUserIssuedCredentialIssuers(TEST_USER_ID))
                .thenReturn(List.of(CRI_PASSPORT, CRI_ADDRESS, CRI_FRAUD, CRI_KBV));

        mockConfigurationServiceMethodCalls();

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/fail", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    private void mockConfigurationServiceMethodCalls() {
        when(mockConfigurationService.getSsmParameter(PASSPORT_CRI_ID)).thenReturn(CRI_PASSPORT);
        when(mockConfigurationService.getSsmParameter(FRAUD_CRI_ID)).thenReturn(CRI_FRAUD);
        when(mockConfigurationService.getSsmParameter(KBV_CRI_ID)).thenReturn(CRI_KBV);
        when(mockConfigurationService.getSsmParameter(ADDRESS_CRI_ID)).thenReturn(CRI_ADDRESS);
    }

    private APIGatewayProxyRequestEvent createRequestEvent() {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", TEST_SESSION_ID));
        return input;
    }

    private Map<String, String> getResponseBodyAsMap(APIGatewayProxyResponseEvent response)
            throws JsonProcessingException {
        return objectMapper.readValue(response.getBody(), Map.class);
    }
}
