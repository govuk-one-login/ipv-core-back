package uk.gov.di.ipv.core.library.sis.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.retry.Sleeper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.sis.dto.SisStoredIdentityCheckDto;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Flow;
import java.util.stream.Stream;

import static org.apache.hc.core5.http.HttpHeaders.AUTHORIZATION;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SisClientTest {
    private static final String SIS_APPLICATION_URL = "http://localhost/v1";
    private static final String SIS_API_KEY = "some-api-key"; // pragma: allowlist secret
    private static final String TEST_JOURNEY_ID = "TEST_JOURNEY_ID";
    private static final List<Vot> TEST_VOTS = List.of(Vot.P1, Vot.P2);
    public static final String TEST_ACCESS_TOKEN = "dummy_access_token";

    @Mock private ConfigService mockConfigService;
    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<String> mockHttpResponse;
    @Mock private Sleeper mockSleeper;
    @Captor ArgumentCaptor<HttpRequest> httpRequestCaptor;
    @InjectMocks private SisClient sisClient;
    @Mock private URI badUri;

    @BeforeEach
    void setUp() {
        when(mockConfigService.getSisApplicationUrl()).thenReturn(URI.create(SIS_APPLICATION_URL));
    }

    @Test
    void getStoredIdentity_returnsEmptyResult_ifBadUrl() {
        // Arrange
        when(mockConfigService.getSisApplicationUrl()).thenReturn(badUri);
        when(badUri.toString()).thenReturn("\\");

        // Act
        var result = sisClient.getStoredIdentity(TEST_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertFalse(result.requestSucceeded());
        assertNull(result.identityDetails());
    }

    @Test
    void getStoredIdentity_retriesRequest_ifSisReturnsErrorCode() throws Exception {
        // Arrange
        when(mockConfigService.getSecret(ConfigurationVariable.SIS_API_KEY))
                .thenReturn(SIS_API_KEY);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);

        when(mockHttpResponse.body())
                .thenReturn((String) getStoredIdentityTestData().findFirst().get().get()[0]);

        when(mockHttpResponse.statusCode())
                .thenReturn(
                        HttpStatusCode.THROTTLING, HttpStatusCode.THROTTLING, HttpStatusCode.OK);

        // Act
        sisClient.getStoredIdentity(TEST_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        verify(mockHttpClient, times(3)).send(any(), any());
        var inOrder = inOrder(mockSleeper);
        inOrder.verify(mockSleeper, times(1)).sleep(1000);
        inOrder.verify(mockSleeper, times(1)).sleep(2000);
        inOrder.verifyNoMoreInteractions();
    }

    @Test
    void getStoredIdentity_returnsEmptyResult_ifRetryRequestLimitExceeded() throws Exception {
        // Arrange
        when(mockConfigService.getSecret(ConfigurationVariable.SIS_API_KEY))
                .thenReturn(SIS_API_KEY);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.body()).thenReturn("{\"message\":\"throttled\"}");
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.THROTTLING);

        // Act
        var result = sisClient.getStoredIdentity(TEST_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertFalse(result.requestSucceeded());
        assertNull(result.identityDetails());

        verify(mockHttpClient, times(4)).send(any(), any());
        var inOrder = inOrder(mockSleeper);
        inOrder.verify(mockSleeper, times(1)).sleep(1000);
        inOrder.verify(mockSleeper, times(1)).sleep(2000);
        inOrder.verify(mockSleeper, times(1)).sleep(4000);
        inOrder.verifyNoMoreInteractions();
    }

    @Test
    void getStoredIdentity_sendsCorrectRequest() throws Exception {
        // Arrange
        when(mockConfigService.getSecret(ConfigurationVariable.SIS_API_KEY))
                .thenReturn(SIS_API_KEY);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.NOT_FOUND);

        // Act
        sisClient.getStoredIdentity(TEST_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
        HttpRequest httpRequest = httpRequestCaptor.getValue();
        assertEquals("POST", httpRequest.method());
        assertEquals("/v1/user-identity", httpRequest.uri().getPath());
        assertTrue(httpRequest.headers().map().containsKey(AUTHORIZATION));
        assertEquals(
                List.of("Bearer dummy_access_token"),
                httpRequest.headers().map().get(AUTHORIZATION));

        assertTrue(httpRequest.bodyPublisher().isPresent());

        var bodySubsrciber = new BodyExtractingSubscriber();
        httpRequest.bodyPublisher().get().subscribe(bodySubsrciber);
        assertEquals(
                """
                {"vtr":["P1","P2"],"govukSigninJourneyId":"TEST_JOURNEY_ID"}""",
                bodySubsrciber.getBody());
    }

    @ParameterizedTest
    @MethodSource("getStoredIdentityTestData")
    void getStoredIdentity_shouldParseResponseCorrectly(
            String responseJson, SisGetStoredIdentityResult expectedResult) throws Exception {
        // Arrange
        when(mockConfigService.getSecret(ConfigurationVariable.SIS_API_KEY))
                .thenReturn(SIS_API_KEY);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.OK);
        when(mockHttpResponse.body()).thenReturn(responseJson);

        // Act
        var result = sisClient.getStoredIdentity(TEST_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(expectedResult, result);
    }

    private static Stream<Arguments> getStoredIdentityTestData() {
        return Stream.of(
                Arguments.of(
                        """
                        { "content": "dummy_JWT", "isValid": true, "expired": false, "vot": "P2", "kidValid": true, "signatureValid": false }
                        """,
                        new SisGetStoredIdentityResult(
                                true,
                                true,
                                new SisStoredIdentityCheckDto(
                                        "dummy_JWT", true, false, Vot.P2, true, false))),
                Arguments.of(
                        """
                        { "content": "dummy_JWT", "isValid": false, "expired": true, "vot": "P1", "kidValid": false, "signatureValid": true }
                        """,
                        new SisGetStoredIdentityResult(
                                true,
                                true,
                                new SisStoredIdentityCheckDto(
                                        "dummy_JWT", false, true, Vot.P1, false, true))));
    }

    @Test
    void getStoredIdentity_returnsFailure_whenJsonIsInvalid() throws Exception {
        // Arrange
        when(mockConfigService.getSecret(ConfigurationVariable.SIS_API_KEY))
                .thenReturn(SIS_API_KEY);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.OK);
        when(mockHttpResponse.body()).thenReturn("not valid json");

        // Act
        var result = sisClient.getStoredIdentity(TEST_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(new SisGetStoredIdentityResult(false, false, null), result);
    }

    @Test
    void getStoredIdentity_returnsFailure_whenHttpErrorReceived() throws Exception {
        // Arrange
        when(mockConfigService.getSecret(ConfigurationVariable.SIS_API_KEY))
                .thenReturn(SIS_API_KEY);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.INTERNAL_SERVER_ERROR);

        // Act
        var result = sisClient.getStoredIdentity(TEST_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(new SisGetStoredIdentityResult(false, false, null), result);
    }

    @Test
    void getStoredIdentity_returnsNotFound_when404Received() throws Exception {
        // Arrange
        when(mockConfigService.getSecret(ConfigurationVariable.SIS_API_KEY))
                .thenReturn(SIS_API_KEY);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.NOT_FOUND);

        // Act
        var result = sisClient.getStoredIdentity(TEST_ACCESS_TOKEN, TEST_VOTS, TEST_JOURNEY_ID);

        // Assert
        assertEquals(new SisGetStoredIdentityResult(true, false, null), result);
    }

    public static class BodyExtractingSubscriber implements Flow.Subscriber<ByteBuffer> {
        private final StringBuilder body = new StringBuilder();

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(ByteBuffer item) {
            body.append(StandardCharsets.UTF_8.decode(item));
        }

        @Override
        public void onError(Throwable throwable) {
            // Not needed for testing
        }

        @Override
        public void onComplete() {
            // Not needed for testing
        }

        public String getBody() {
            return body.toString();
        }
    }
}
