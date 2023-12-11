package uk.gov.di.ipv.core.library.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.FEATURE_SET_HEADER;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IPV_SESSION_ID_HEADER;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IP_ADDRESS_HEADER;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getClientOAuthSessionId;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getFeatureSet;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getHeaderByKey;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionIdAllowNull;

class RequestHelperTest {
    private final String TEST_IPV_SESSION_ID = "a-session-id";
    private final String TEST_IP_ADDRESS = "127.0.0.1";
    private final String TEST_FEATURE_SET = "test-feature-set";
    private final String TEST_CLIENT_SESSION_ID = "client-session-id";
    private final String TEST_JOURNEY = DCMAW_CRI;
    private static final String CONTEXT = "context";
    private static final String BANK_ACCOUNT_CONTEXT = "context";
    private static final String TEST_JOURNEY_WITH_CONTEXT =
            String.format("claimedIdentity?%s=%s", CONTEXT, BANK_ACCOUNT_CONTEXT);
    private static final String SCOPE = "scope";
    private static final String IDENTITY_CHECK_SCOPE = "identityCheck";
    private static final String TEST_JOURNEY_WITH_SCOPE =
            String.format("claimedIdentity?%s=%s", SCOPE, IDENTITY_CHECK_SCOPE);
    private static final String TEST_JOURNEY_WITH_CONTEXT_AND_SCOPE =
            String.format(
                    "claimedIdentity?%s=%s&%s=%s",
                    CONTEXT, BANK_ACCOUNT_CONTEXT, SCOPE, IDENTITY_CHECK_SCOPE);

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

        assertEquals("a-session-id", getIpvSessionId(event));
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
        assertEquals(ipvSessionId, getIpvSessionId(event));
        assertEquals(ipAddress, getIpAddress(event));
        assertEquals(featureSet, getFeatureSet(event));
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
        assertEquals(TEST_FEATURE_SET, getFeatureSet(event));
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
        assertNull(getFeatureSet(event));
    }

    @ParameterizedTest
    @MethodSource("journeyUriParameters")
    void getJourneyShouldReturnJourneyWithParametersFromJourneyRequest(
            String journey, String expectedContext, String expectedScope) {
        var event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_IPV_SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .journey(journey)
                        .build();

        URI journeyUri = URI.create(event.getJourney());
        assertEquals(CLAIMED_IDENTITY_CRI, journeyUri.getPath());
        assertEquals(expectedContext, RequestHelper.getURIParameter(journeyUri, CONTEXT));
        assertEquals(expectedScope, RequestHelper.getURIParameter(journeyUri, SCOPE));
    }

    static Stream<Arguments> journeyUriParameters() {
        return Stream.of(
                Arguments.of(TEST_JOURNEY_WITH_CONTEXT, BANK_ACCOUNT_CONTEXT, null),
                Arguments.of(TEST_JOURNEY_WITH_SCOPE, null, IDENTITY_CHECK_SCOPE),
                Arguments.of(
                        TEST_JOURNEY_WITH_CONTEXT_AND_SCOPE,
                        BANK_ACCOUNT_CONTEXT,
                        IDENTITY_CHECK_SCOPE));
    }

    @Test
    void getScoreTypeShouldReturnScoreType() throws HttpResponseExceptionWithErrorBody {
        ProcessRequest processRequest =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("scoreType", "fraud"))
                        .build();
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
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("scoreThreshold", 2))
                        .build();
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
    void getJourneyTypeShouldReturnJourneyType() throws HttpResponseExceptionWithErrorBody {
        ProcessRequest processRequest =
                ProcessRequest.processRequestBuilder()
                        .lambdaInput(Map.of("journeyType", "reuse"))
                        .build();
        assertEquals("reuse", RequestHelper.getJourneyType(processRequest));
    }

    @Test
    void getJourneyTypeShouldThrowIfJourneyTypeIsNull() {
        ProcessRequest processRequest = new ProcessRequest();

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getJourneyType(processRequest));

        assertEquals(HttpStatus.SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_JOURNEY_TYPE.getMessage(),
                exception.getErrorResponse().getMessage());
    }
}
