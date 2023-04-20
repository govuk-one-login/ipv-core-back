package uk.gov.di.ipv.core.library.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IPV_SESSION_ID_HEADER;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IP_ADDRESS_HEADER;

class RequestHelperTest {

    private final Map<String, String> headers =
            Map.of(
                    "foo", "bar",
                    "Foo", "bar",
                    "baz", "bar");

    @ParameterizedTest(name = "with matching header: {0}")
    @ValueSource(strings = {"Baz", "baz"})
    void matchHeaderByDownCasing(String headerName) {
        assertEquals("bar", RequestHelper.getHeader(headers, headerName).get());
    }

    @ParameterizedTest(name = "with non-matching header: {0}")
    @ValueSource(strings = {"boo", "", "foo", "Foo"})
    void noMatchingHeader(String headerName) {
        assertTrue(RequestHelper.getHeader(headers, headerName).isEmpty());
    }

    @Test
    void getHeaderShouldReturnEmptyOptionalIfHeadersIsNull() {
        Optional<String> result = RequestHelper.getHeader(null, "someHeader");
        assertTrue(result.isEmpty());
    }

    @Test
    void getHeaderShouldReturnEmptyOptionalIfHeaderValueIsBlank() {
        Map<String, String> blank1 = Map.of("illbeblank", "");
        Map<String, String> blank2 = new HashMap<>();
        blank2.put("illbeblank", null);

        for (Map<String, String> headers : List.of(blank1, blank2)) {
            assertTrue(RequestHelper.getHeader(headers, "illbeblank").isEmpty());
        }
    }

    @Test
    void getHeaderByKeyShouldReturnNullIfHeaderNotFound() {
        assertNull(RequestHelper.getHeaderByKey(Map.of("tome", "toyou"), "ohdearohdear"));
    }

    @Test
    void getIpvSessionIdShouldReturnSessionId() throws HttpResponseExceptionWithErrorBody {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER, "a-session-id"));

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
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getIpvSessionId(event));

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
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getIpvSessionId(event));

        assertEquals(HttpStatus.SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getIpvSessionIdShouldReturnNullIfSessionIdIsNull()
            throws HttpResponseExceptionWithErrorBody {
        var event = new APIGatewayProxyRequestEvent();
        HashMap<String, String> headers = new HashMap<>();
        headers.put(IPV_SESSION_ID_HEADER, null);

        event.setHeaders(headers);

        assertNull(RequestHelper.getIpvSessionIdAllowNull(event));
    }

    @Test
    void getIpvSessionIdShouldReturnNullIfSessionIdIsEmpty()
            throws HttpResponseExceptionWithErrorBody {
        var event = new APIGatewayProxyRequestEvent();
        HashMap<String, String> headers = new HashMap<>();
        headers.put(IPV_SESSION_ID_HEADER, "");

        event.setHeaders(headers);

        assertNull(RequestHelper.getIpvSessionIdAllowNull(event));
    }

    @Test
    void getIpAddressShouldReturnIpAddress() throws HttpResponseExceptionWithErrorBody {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(IP_ADDRESS_HEADER, "a-client-source-ip"));

        assertEquals("a-client-source-ip", RequestHelper.getIpAddress(event));
    }

    @Test
    void getIpAddressShouldThrowIfIpAddressIsNull() {
        var event = new APIGatewayProxyRequestEvent();
        HashMap<String, String> headers = new HashMap<>();
        headers.put(IP_ADDRESS_HEADER, null);

        event.setHeaders(headers);

        var exception =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getIpAddress(event));

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
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> RequestHelper.getIpAddress(event));

        assertEquals(HttpStatus.SC_BAD_REQUEST, exception.getResponseCode());
        assertEquals(
                ErrorResponse.MISSING_IP_ADDRESS.getMessage(),
                exception.getErrorResponse().getMessage());
    }

    @Test
    void getClientOAuthSessionIdShouldReturnClientSessionId() {
        var event = new APIGatewayProxyRequestEvent();
        String clientSessionIdInHeader = "client-session-id";
        event.setHeaders(Map.of(CLIENT_SESSION_ID_HEADER, clientSessionIdInHeader));

        assertEquals(clientSessionIdInHeader, RequestHelper.getClientOAuthSessionId(event));
    }

    @Test
    void getClientOAuthSessionIdShouldReturnNullIfClientSessionIdIsNull() {
        var event = new APIGatewayProxyRequestEvent();
        HashMap<String, String> headers = new HashMap<>();
        headers.put(CLIENT_SESSION_ID_HEADER, null);
        event.setHeaders(headers);

        assertNull(RequestHelper.getClientOAuthSessionId(event));
    }
}
