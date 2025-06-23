package uk.gov.di.ipv.core.library.evcs.client;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.core5.net.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsPostIdentityDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsStoredIdentityDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsUpdateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.fixtures.VcFixtures;
import uk.gov.di.ipv.core.library.retry.Sleeper;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.apache.hc.core5.http.HttpHeaders.AUTHORIZATION;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.evcs.client.EvcsClient.VC_STATE_PARAM;
import static uk.gov.di.ipv.core.library.evcs.client.EvcsClient.X_API_KEY_HEADER;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;

@ExtendWith(MockitoExtension.class)
class EvcsClientTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String EVCS_APPLICATION_URL = "http://localhost/v1";
    private static final String EVCS_APPLICATION_URL_WITH_V1_VCS = "http://localhost/v1/ver2";
    private static final String EVCS_API_KEY =
            "L2BGccX59Ea9PMJ3ipu9t7r99ykD2Tlh1KYpdjdg"; // pragma: allowlist secret
    private static final String TEST_EVCS_ACCESS_TOKEN = "TEST_EVCS_ACCESS_TOKEN";
    private static final String TEST_USER_ID = "urn:uuid:9bd7f130-4238-4532-83cd-01cb29584834";
    private static final Map<String, Object> TEST_METADATA =
            Map.of(
                    "reason", "testing",
                    "txmaEventId", "txma-event-id-2",
                    "timestampMs", "1714478033959");
    private static final EvcsGetUserVCsDto EVCS_GET_USER_VCS_DTO =
            new EvcsGetUserVCsDto(
                    List.of(
                            new EvcsGetUserVCDto(
                                    VcFixtures.vcAddressOne().getVcString(),
                                    EvcsVCState.CURRENT,
                                    TEST_METADATA),
                            new EvcsGetUserVCDto(
                                    VcFixtures.vcWebDrivingPermitDvaValid().getVcString(),
                                    EvcsVCState.PENDING_RETURN,
                                    TEST_METADATA)));
    private static final List<EvcsCreateUserVCsDto> EVCS_CREATE_USER_VCS_DTO =
            List.of(
                    new EvcsCreateUserVCsDto(
                            VcFixtures.vcAddressOne().getVcString(),
                            EvcsVCState.CURRENT,
                            TEST_METADATA,
                            null),
                    new EvcsCreateUserVCsDto(
                            VcFixtures.vcWebDrivingPermitDvaValid().getVcString(),
                            EvcsVCState.CURRENT,
                            TEST_METADATA,
                            null));
    private static final List<EvcsUpdateUserVCsDto> EVCS_UPDATE_USER_VCS_DTO =
            List.of(
                    new EvcsUpdateUserVCsDto("VC_Signature1", EvcsVCState.HISTORIC, TEST_METADATA),
                    new EvcsUpdateUserVCsDto(
                            "VC_Signature2", EvcsVCState.ABANDONED, TEST_METADATA));
    private static final EvcsPostIdentityDto EVCS_POST_IDENTITY_DTO_SI_ONLY =
            new EvcsPostIdentityDto(
                    TEST_USER_ID, null, new EvcsStoredIdentityDto("storedIdentityJwt", Vot.P2));
    private static final List<EvcsVCState> VC_STATES_FOR_QUERY = List.of(CURRENT, PENDING_RETURN);

    @Mock private ConfigService mockConfigService;
    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<String> mockHttpResponse;
    @Mock private Sleeper mockSleeper;
    @Captor ArgumentCaptor<HttpRequest> httpRequestCaptor;
    @Captor private ArgumentCaptor<String> stringCaptor;
    @InjectMocks private EvcsClient evcsClient;

    @BeforeEach
    void setUp() {
        when(mockConfigService.getParameter(ConfigurationVariable.EVCS_APPLICATION_URL))
                .thenReturn(EVCS_APPLICATION_URL);
        lenient()
                .when(mockConfigService.getSecret(ConfigurationVariable.EVCS_API_KEY))
                .thenReturn(EVCS_API_KEY);
    }

    @ParameterizedTest
    @ValueSource(strings = {EVCS_APPLICATION_URL, EVCS_APPLICATION_URL_WITH_V1_VCS})
    void testGetUserVCs(String appUrl) throws Exception {
        when(mockConfigService.getParameter(ConfigurationVariable.EVCS_APPLICATION_URL))
                .thenReturn(appUrl);
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.OK);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(EVCS_GET_USER_VCS_DTO));

        // Act
        var evcsGetUserVCsDto =
                evcsClient.getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY);

        // Assert
        verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
        HttpRequest httpRequest = httpRequestCaptor.getValue();
        assertEquals("GET", httpRequest.method());
        assertTrue(httpRequest.headers().map().containsKey(AUTHORIZATION));
        assertTrue(httpRequest.headers().map().containsKey(X_API_KEY_HEADER));
        var baseUri =
                "%s/vcs/%s"
                        .formatted(appUrl, URLEncoder.encode(TEST_USER_ID, StandardCharsets.UTF_8));
        var expectedUri =
                new URIBuilder(baseUri)
                        .addParameter(
                                VC_STATE_PARAM,
                                VC_STATES_FOR_QUERY.stream()
                                        .map(EvcsVCState::name)
                                        .collect(Collectors.joining(",")))
                        .build();
        assertEquals(expectedUri.toString(), httpRequest.uri().toString());
        assertEquals(2, evcsGetUserVCsDto.vcs().size());
    }

    @Test
    void testGetUserVCs_emptyListIsReturned() throws Exception {
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.OK);
        when(mockHttpResponse.body())
                .thenReturn(
                        OBJECT_MAPPER.writeValueAsString(
                                new EvcsGetUserVCsDto(Collections.emptyList())));
        // Act
        evcsClient.getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY);

        // Assert
        verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
        HttpRequest httpRequest = httpRequestCaptor.getValue();
        assertEquals("GET", httpRequest.method());
        assertTrue(httpRequest.headers().map().containsKey(AUTHORIZATION));
        assertTrue(httpRequest.headers().map().containsKey(X_API_KEY_HEADER));
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 500})
    void testGetUserVCs_shouldThrowException_ifNon200ResponseStatus(int statusCode)
            throws Exception {
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.body()).thenReturn("{\"message\":\"Forbidden\"}");
        when(mockHttpResponse.statusCode()).thenReturn(statusCode);
        // Act
        // Assert
        var e =
                assertThrows(
                        EvcsServiceException.class,
                        () ->
                                evcsClient.getUserVcs(
                                        TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY));

        assertEquals(ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE, e.getErrorResponse());
    }

    @Test
    void testGetUserVCs_shouldNotThrowException_for404ResponseStatus() throws Exception {
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(404);
        // Act
        // Assert
        var evcsGetUserVCsDto =
                evcsClient.getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY);

        // Assert
        verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
        HttpRequest httpRequest = httpRequestCaptor.getValue();
        assertEquals("GET", httpRequest.method());
        assertTrue(httpRequest.headers().map().containsKey(AUTHORIZATION));
        assertTrue(httpRequest.headers().map().containsKey(X_API_KEY_HEADER));
        assertEquals(0, evcsGetUserVCsDto.vcs().size());
    }

    @Test
    void testGetUserVCs_shouldThrowException_non200Response_failedParsingResponseBody()
            throws Exception {
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(500);
        when(mockHttpResponse.body()).thenReturn("{}}");
        // Act
        // Assert
        assertThrows(
                EvcsServiceException.class,
                () ->
                        evcsClient.getUserVcs(
                                TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY));
    }

    @Test
    void testGetUserVCs_shouldThrowException_ifHttpClientException() throws Exception {
        // Arrange
        when(mockHttpClient.send(any(), any())).thenThrow(new InterruptedException());
        // Act
        // Assert
        assertThrows(
                EvcsServiceException.class,
                () ->
                        evcsClient.getUserVcs(
                                TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY));
    }

    @Test
    void testGetUserVCs_shouldThrowException_ifResponseBodyParsingFail() throws Exception {
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.OK);
        when(mockHttpResponse.body()).thenReturn("🐛");
        // Act
        // Assert
        assertThrows(
                EvcsServiceException.class,
                () ->
                        evcsClient.getUserVcs(
                                TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY));
    }

    @Test
    void testGetUserVCs_shouldThrowException_ifBadUrl() {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.EVCS_APPLICATION_URL))
                .thenReturn("\\");
        // Act
        // Assert
        assertThrows(
                EvcsServiceException.class,
                () ->
                        evcsClient.getUserVcs(
                                "user %^", TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY));
    }

    @Test
    void testCreateUserVCs() throws Exception {
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.ACCEPTED);
        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            evcsClient.storeUserVCs(TEST_USER_ID, EVCS_CREATE_USER_VCS_DTO);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            HttpRequest httpRequest = httpRequestCaptor.getValue();
            assertEquals("POST", httpRequest.method());
            assertTrue(httpRequest.bodyPublisher().isPresent());
            assertFalse(httpRequest.headers().map().containsKey(AUTHORIZATION));
            assertTrue(httpRequest.headers().map().containsKey(X_API_KEY_HEADER));

            mockedBodyPublishers.verify(
                    () -> HttpRequest.BodyPublishers.ofString(stringCaptor.capture()));
            var userVCsForEvcs =
                    OBJECT_MAPPER.readValue(
                            stringCaptor.getAllValues().get(0),
                            new TypeReference<List<EvcsCreateUserVCsDto>>() {});
            assertFalse(userVCsForEvcs.stream().anyMatch(dto -> !dto.state().equals(CURRENT)));
        }
    }

    @Test
    void testCreateUserVCs_shouldThrowException_ifBadUrl() {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.EVCS_APPLICATION_URL))
                .thenReturn("\\");
        // Act
        // Assert
        assertThrows(
                EvcsServiceException.class,
                () -> evcsClient.storeUserVCs("user%^", EVCS_CREATE_USER_VCS_DTO));
    }

    @Test
    void testUpdateUserVCs() throws Exception {
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.ACCEPTED);
        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            evcsClient.updateUserVCs(TEST_USER_ID, EVCS_UPDATE_USER_VCS_DTO);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            HttpRequest httpRequest = httpRequestCaptor.getValue();
            assertEquals("PATCH", httpRequest.method());
            assertTrue(httpRequest.bodyPublisher().isPresent());
            assertFalse(httpRequest.headers().map().containsKey(AUTHORIZATION));
            assertTrue(httpRequest.headers().map().containsKey(X_API_KEY_HEADER));

            mockedBodyPublishers.verify(
                    () -> HttpRequest.BodyPublishers.ofString(stringCaptor.capture()));
            var userVCsForEvcs =
                    OBJECT_MAPPER.readValue(
                            stringCaptor.getAllValues().get(0),
                            new TypeReference<List<EvcsUpdateUserVCsDto>>() {});
            assertFalse(userVCsForEvcs.stream().anyMatch(dto -> dto.state().equals(CURRENT)));
        }
    }

    @Test
    void testUpdateUserVCs_shouldThrowException_ifBadUrl() {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.EVCS_APPLICATION_URL))
                .thenReturn("\\");
        // Act
        // Assert
        assertThrows(
                EvcsServiceException.class,
                () -> evcsClient.updateUserVCs("user%^", EVCS_UPDATE_USER_VCS_DTO));
    }

    @Test
    void testGetUserVCsShouldRetryRequestIfStatusCode429() throws Exception {
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);

        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(EVCS_GET_USER_VCS_DTO));

        when(mockHttpResponse.statusCode()).thenReturn(429, 429, 200);

        // Act
        var evcsGetUserVCsDto =
                evcsClient.getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY);
        // Assert
        assertEquals(2, evcsGetUserVCsDto.vcs().size());
        verify(mockHttpClient, times(3)).send(any(), any());
        var inOrder = inOrder(mockSleeper);
        inOrder.verify(mockSleeper, times(1)).sleep(1000);
        inOrder.verify(mockSleeper, times(1)).sleep(2000);
        inOrder.verifyNoMoreInteractions();
    }

    @Test
    void testThrowExceptionIfRetryRequestLimitExceeded() throws Exception {
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.body()).thenReturn("{\"message\":\"throttled\"}");
        when(mockHttpResponse.statusCode()).thenReturn(429);

        // Act
        // Assert
        assertThrows(
                EvcsServiceException.class,
                () ->
                        evcsClient.getUserVcs(
                                TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY));
        verify(mockHttpClient, times(4)).send(any(), any());
        var inOrder = inOrder(mockSleeper);
        inOrder.verify(mockSleeper, times(1)).sleep(1000);
        inOrder.verify(mockSleeper, times(1)).sleep(2000);
        inOrder.verify(mockSleeper, times(1)).sleep(4000);
        inOrder.verifyNoMoreInteractions();
    }

    @Test
    void storeUserIdentityShouldSuccessfullySendRequest() throws Exception {
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.ACCEPTED);
        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            evcsClient.storeUserIdentity(EVCS_POST_IDENTITY_DTO_SI_ONLY);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            HttpRequest httpRequest = httpRequestCaptor.getValue();
            assertEquals("POST", httpRequest.method());
            assertTrue(httpRequest.bodyPublisher().isPresent());
            assertFalse(httpRequest.headers().map().containsKey(AUTHORIZATION));
            assertTrue(httpRequest.headers().map().containsKey(X_API_KEY_HEADER));

            mockedBodyPublishers.verify(
                    () -> HttpRequest.BodyPublishers.ofString(stringCaptor.capture()));
            var evcsPostIdentityDto =
                    OBJECT_MAPPER.readValue(
                            stringCaptor.getAllValues().get(0),
                            new TypeReference<EvcsPostIdentityDto>() {});
            assertEquals("storedIdentityJwt", evcsPostIdentityDto.si().jwt());
            assertEquals(Vot.P2, evcsPostIdentityDto.si().vot());
            assertEquals(TEST_USER_ID, evcsPostIdentityDto.userId());
        }
    }
}
