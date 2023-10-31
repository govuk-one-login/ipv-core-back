package uk.gov.di.ipv.core.library.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.*;

class RequestHelperTest {
    private final String TEST_IPV_SESSION_ID = "a-session-id";
    private final String TEST_IP_ADDRESS = "127.0.0.1";
    private final String TEST_FEATURE_SET = "test-feature-set";
    private final String TEST_CLIENT_SESSION_ID = "client-session-id";
    private final String TEST_JOURNEY = DCMAW_CRI;
    private static final String TEST_SCOPE = "identityCheck";

    @Test
    void getHeaderByKeyShouldReturnNullIfHeaderNotFound() {
        assertNull(getHeaderByKey(Map.of("tome", "toyou"), "ohdearohdear"));
    }

    @Test
    void getHeaderByKeyShouldReturnNullIfHeaderPassedNull() {
        assertNull(getHeaderByKey(null, "ohdearohdear"));
    }

    @Test
    void getIpvSessionIdShouldReturnSessionId() throws HttpResponseExceptionWithErrorBody {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER, "a-session-id"));

        assertEquals("a-session-id", getIpvSessionId(event));
    }

    @Test
    void getIpvSessionIdShouldReturnSessionIdFromJourney()
            throws HttpResponseExceptionWithErrorBody {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_IPV_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .build();

        assertEquals("a-session-id", RequestHelper.getIpvSessionId(event));
    }

    @Test
    void getIpvSessionIdShouldThrowIfSessionIdIsNull() {
        var event = new APIGatewayProxyRequestEvent();
        HashMap<String, String> headers = new HashMap<>();
        headers.put(IPV_SESSION_ID_HEADER, null);

        event.setHeaders(headers);

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class, () -> getIpvSessionId(event));

        assertEquals(HttpStatus.SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getIpvSessionIdShouldThrowIfSessionIdIsEmptyString() {
        var event = new APIGatewayProxyRequestEvent();

        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER, ""));

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class, () -> getIpvSessionId(event));

        assertEquals(HttpStatus.SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getIpAddressShouldReturnIpAddress() throws HttpResponseExceptionWithErrorBody {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(IP_ADDRESS_HEADER, "a-client-source-ip"));

        assertEquals("a-client-source-ip", getIpAddress(event));
    }

    @Test
    void getIpAddressShouldThrowIfIpAddressIsNull() {
        var event = new APIGatewayProxyRequestEvent();
        HashMap<String, String> headers = new HashMap<>();
        headers.put(IP_ADDRESS_HEADER, null);

        event.setHeaders(headers);

        var exception =
                assertThrows(HttpResponseExceptionWithErrorBody.class, () -> getIpAddress(event));

        assertEquals(HttpStatus.SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_IP_ADDRESS.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getIpAddressIdShouldThrowIfIpAddressIsEmptyString() {
        var event = new APIGatewayProxyRequestEvent();

        event.setHeaders(Map.of(IP_ADDRESS_HEADER, ""));

        var exception =
                assertThrows(HttpResponseExceptionWithErrorBody.class, () -> getIpAddress(event));

        assertEquals(HttpStatus.SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_IP_ADDRESS.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getClientOAuthSessionIdShouldReturnClientSessionId() {
        var event = new JourneyRequest();
        String clientSessionIdInHeader = "client-session-id";
        event.setClientOAuthSessionId(clientSessionIdInHeader);

        assertEquals(clientSessionIdInHeader, getClientOAuthSessionId(event));
    }

    @Test
    void getClientOAuthSessionIdShouldReturnNullIfClientSessionIdIsNull() {
        var event = new JourneyRequest();
        event.setClientOAuthSessionId(null);

        assertNull(getClientOAuthSessionId(event));
    }

    @Test
    void forJourneyRequestShouldReturnClientSessionId() throws HttpResponseExceptionWithErrorBody {
        String clientSessionId = "client-session-id";
        String ipvSessionId = "a-session-id";
        String ipAddress = "a-ipaddress";
        String featureSet = "a-feature-set";
        String journey = DCMAW_CRI;
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(ipvSessionId)
                        .ipAddress(ipAddress)
                        .clientOAuthSessionId(clientSessionId)
                        .journey(journey)
                        .featureSet(featureSet)
                        .build();

        assertEquals(clientSessionId, getClientOAuthSessionId(event));
        assertEquals(ipvSessionId, RequestHelper.getIpvSessionId(event));
        assertEquals(ipAddress, RequestHelper.getIpAddress(event));
        assertEquals(featureSet, RequestHelper.getFeatureSet(event));
    }

    @Test
    void forJourneyRequestShouldReturnNullIfSessionIdIsNull()
            throws HttpResponseExceptionWithErrorBody {
        String clientSessionId = "client-session-id";
        String ipAddress = "a-ipaddress";
        String featureSet = "a-feature-set";
        String journey = DCMAW_CRI;
        var event =
                JourneyRequest.builder()
                        .ipAddress(ipAddress)
                        .clientOAuthSessionId(clientSessionId)
                        .journey(journey)
                        .featureSet(featureSet)
                        .build();

        assertNull(getIpvSessionIdAllowNull(event));
    }

    @Test
    void getFeatureSetShouldReturnFeatureSetId() {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(FEATURE_SET_HEADER, TEST_FEATURE_SET));

        assertEquals(TEST_FEATURE_SET, getFeatureSet(event));
    }

    @Test
    void getFeatureSetShouldReturnFeatureSetIdFromJourney() {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_IPV_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .build();
        assertEquals(TEST_FEATURE_SET, RequestHelper.getFeatureSet(event));
    }

    @Test
    void getFeatureSetShouldReturnNullFromJourneyifNoFeatureSet() {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_IPV_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .journey(TEST_JOURNEY)
                        .build();
        assertNull(RequestHelper.getFeatureSet(event));
    }

    @Test
    void getJourneyShouldReturnJourneyFromJourneyRequest() {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_IPV_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .journey(TEST_JOURNEY)
                        .build();
        assertEquals(TEST_JOURNEY, RequestHelper.getJourney(event));
    }

    @Test
    void getScoreTypeShouldReturnScoreType() throws HttpResponseExceptionWithErrorBody {
        ProcessRequest processRequest =
                ProcessRequest.processRequestBuilder().scoreType("fraud").build();
        assertEquals("fraud", RequestHelper.getScoreType(processRequest));
    }

    @Test
    void getScoreTypeShouldThrowIfScoreTypeIsNull() {
        ProcessRequest processRequest = new ProcessRequest();

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getScoreType(processRequest));

        assertEquals(HttpStatus.SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_SCORE_TYPE.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getScoreThresholdShouldReturnScoreThreshold() throws HttpResponseExceptionWithErrorBody {
        ProcessRequest processRequest =
                ProcessRequest.processRequestBuilder().scoreThreshold(2).build();
        assertEquals(2, RequestHelper.getScoreThreshold(processRequest));
    }

    @Test
    void getScoreThresholdShouldThrowIfScoreThresholdIsNull() {
        ProcessRequest processRequest = new ProcessRequest();

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getScoreThreshold(processRequest));

        assertEquals(HttpStatus.SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_SCORE_THRESHOLD.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getCriScopeShouldReturnScopeFromJourneyRequest() {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_IPV_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .journey(TEST_JOURNEY)
                        .scope(TEST_SCOPE)
                        .build();
        assertEquals(TEST_SCOPE, RequestHelper.getCriScope(event));
    }
}
