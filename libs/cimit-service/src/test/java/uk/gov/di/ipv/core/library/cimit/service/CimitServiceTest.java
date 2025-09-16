package uk.gov.di.ipv.core.library.cimit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
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
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.cimit.domain.CimitApiResponse;
import uk.gov.di.ipv.core.library.cimit.dto.ContraIndicatorCredentialDto;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.domain.CimitConfig;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.cimit.service.CimitService.FAILED_RESPONSE;
import static uk.gov.di.ipv.core.library.cimit.service.CimitService.IP_ADDRESS_HEADER;
import static uk.gov.di.ipv.core.library.cimit.service.CimitService.X_API_KEY_HEADER;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CIMIT_API_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;

@ExtendWith(MockitoExtension.class)
class CimitServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String GOVUK_SIGNIN_JOURNEY_ID = "a-journey-id";
    private static final String TEST_USER_ID = "a-user-id";
    private static final String CLIENT_SOURCE_IP = "a-client-source-ip";
    private static final String CIMIT_COMPONENT_ID = "https://identity.staging.account.gov.uk";
    private static final CimitApiResponse SUCCESSFUL_POST_HTTP_RESPONSE =
            new CimitApiResponse("success", null, null);
    private static final ContraIndicatorCredentialDto SUCCESSFUL_GET_CI_HTTP_RESPONSE =
            new ContraIndicatorCredentialDto(SIGNED_CONTRA_INDICATOR_VC_1);
    private static final CimitApiResponse FAILED_CIMIT_HTTP_RESPONSE =
            new CimitApiResponse(FAILED_RESPONSE, "INTERNAL_ERROR", "Internal Server Error");
    private static final String CIMIT_API_BASE_URL = "https://base-url.co.uk";
    private static final String MOCK_CIMIT_API_KEY = "mock-api-key"; // pragma: allowlist secret

    @Captor private ArgumentCaptor<HttpRequest> httpRequestCaptor;
    @Captor private ArgumentCaptor<String> stringCaptor;
    @Mock private ConfigService configService;
    @Mock private Config mockConfig;
    @Mock private CimitConfig mockCimit;

    @Mock private VerifiableCredentialValidator verifiableCredentialValidator;
    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<String> mockHttpResponse;
    @Mock private IpvSessionService ipvSessionService;
    @InjectMocks CimitService cimitService;

    @BeforeEach
    void setUp() {
        when(configService.getConfiguration()).thenReturn(mockConfig);
        when(mockConfig.getCimit()).thenReturn(mockCimit);

        when(mockCimit.getApiBaseUrl()).thenReturn(URI.create(CIMIT_API_BASE_URL));
        when(configService.getSecret(CIMIT_API_KEY)).thenReturn(MOCK_CIMIT_API_KEY);
    }

    private void stubFetchPrereqs() {
        when(mockCimit.getComponentId()).thenReturn(URI.create(CIMIT_COMPONENT_ID));
        when(mockCimit.getSigningKey()).thenReturn(TEST_EC_PUBLIC_JWK);
    }

    @Test
    void submitVcSendsHttpRequestToApi() throws Exception {
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(SUCCESSFUL_POST_HTTP_RESPONSE));

        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            cimitService.submitVC(
                    vcWebPassportSuccessful(), GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            HttpRequest httpRequest = httpRequestCaptor.getValue();
            assertEquals("POST", httpRequest.method());
            assertTrue(httpRequest.bodyPublisher().isPresent());
            assertTrue(httpRequest.headers().map().containsKey(X_API_KEY_HEADER));
            assertTrue(httpRequest.headers().map().containsKey(IP_ADDRESS_HEADER));
            assertTrue(
                    httpRequest
                            .headers()
                            .map()
                            .containsKey(CimitService.GOVUK_SIGNIN_JOURNEY_ID_HEADER));

            mockedBodyPublishers.verify(
                    () -> HttpRequest.BodyPublishers.ofString(stringCaptor.capture()));
        }
    }

    @Test
    void submitVCThrowsIfHttpRequestReturnsFailResponse() throws Exception {
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(FAILED_CIMIT_HTTP_RESPONSE));

        // Act/Assert
        assertThrows(
                CiPutException.class,
                () ->
                        cimitService.submitVC(
                                vcWebPassportSuccessful(),
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP));
    }

    @Test
    void submitMitigationVCListSendsHttpRequestToApi() throws Exception {
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(SUCCESSFUL_POST_HTTP_RESPONSE));

        var vcs = List.of(vcWebPassportSuccessful());
        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            cimitService.submitMitigatingVcList(vcs, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            HttpRequest httpRequest = httpRequestCaptor.getValue();
            assertEquals("POST", httpRequest.method());
            assertTrue(httpRequest.bodyPublisher().isPresent());
            assertTrue(httpRequest.headers().map().containsKey(X_API_KEY_HEADER));
            assertTrue(httpRequest.headers().map().containsKey(IP_ADDRESS_HEADER));
            assertTrue(
                    httpRequest
                            .headers()
                            .map()
                            .containsKey(CimitService.GOVUK_SIGNIN_JOURNEY_ID_HEADER));

            mockedBodyPublishers.verify(
                    () -> HttpRequest.BodyPublishers.ofString(stringCaptor.capture()));
        }
    }

    @Test
    void submitMitigationVCThrowsIfHttpRequestReturnsFailedResponse() throws Exception {
        // Arrange
        var vcs = List.of(vcWebPassportSuccessful());

        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(FAILED_CIMIT_HTTP_RESPONSE));

        // Act/Assert
        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        cimitService.submitMitigatingVcList(
                                vcs, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    private static Stream<Arguments> provideArgumentsForFetchContraIndicatorsVc() throws Exception {
        var contraIndicatorVc =
                VerifiableCredential.fromValidJwt(
                        TEST_USER_ID, null, SignedJWT.parse(SIGNED_CONTRA_INDICATOR_VC_1));
        var otherContraIndicatorVc =
                VerifiableCredential.fromValidJwt(
                        TEST_USER_ID, null, SignedJWT.parse(SIGNED_CONTRA_INDICATOR_VC_2));
        return Stream.of(
                Arguments.of(
                        new IpvSessionItem(),
                        contraIndicatorVc,
                        contraIndicatorVc.getVcString(),
                        true),
                Arguments.of(
                        IpvSessionItem.builder()
                                .securityCheckCredential(contraIndicatorVc.getVcString())
                                .build(),
                        otherContraIndicatorVc,
                        otherContraIndicatorVc.getVcString(),
                        true),
                Arguments.of(
                        IpvSessionItem.builder()
                                .securityCheckCredential(contraIndicatorVc.getVcString())
                                .build(),
                        contraIndicatorVc,
                        contraIndicatorVc.getVcString(),
                        false));
    }

    @ParameterizedTest
    @MethodSource("provideArgumentsForFetchContraIndicatorsVc")
    void sendsHttpRequestToCimitApiAndStoresInSession(
            IpvSessionItem ipvSessionItem,
            VerifiableCredential vcFromCimit,
            String expectedStoredVc,
            boolean hasSecurityCheckCredentialBeenUpdated)
            throws Exception {
        // Arrange
        stubFetchPrereqs();
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.OK);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(SUCCESSFUL_GET_CI_HTTP_RESPONSE));
        when(verifiableCredentialValidator.parseAndValidate(
                        eq(TEST_USER_ID),
                        eq(null),
                        eq(SIGNED_CONTRA_INDICATOR_VC_1),
                        any(),
                        eq(CIMIT_COMPONENT_ID),
                        eq(false)))
                .thenReturn(vcFromCimit);

        // Act
        cimitService.fetchContraIndicatorsVc(
                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP, ipvSessionItem);

        // Assert
        verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
        HttpRequest httpRequest = httpRequestCaptor.getValue();
        assertEquals("GET", httpRequest.method());
        assertTrue(httpRequest.headers().map().containsKey(X_API_KEY_HEADER));
        assertTrue(httpRequest.headers().map().containsKey(IP_ADDRESS_HEADER));
        assertTrue(
                httpRequest
                        .headers()
                        .map()
                        .containsKey(CimitService.GOVUK_SIGNIN_JOURNEY_ID_HEADER));

        assertEquals(expectedStoredVc, ipvSessionItem.getSecurityCheckCredential());
        verify(ipvSessionService, times(hasSecurityCheckCredentialBeenUpdated ? 1 : 0))
                .updateIpvSession(any());
    }

    @Test
    void fetchContraIndicatorsVcVCThrowsExceptionIfHttpRequestReturnsFailedResponse()
            throws Exception {
        // Arrange
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.INTERNAL_SERVER_ERROR);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(FAILED_CIMIT_HTTP_RESPONSE));

        // Act/Assert
        assertThrows(
                CiRetrievalException.class,
                () ->
                        cimitService.fetchContraIndicatorsVc(
                                TEST_USER_ID,
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP,
                                new IpvSessionItem()));
    }

    @Test
    void fetchContraIndicatorsVcVCThrowsExceptionIfHttpRequestIsInterrupted() throws Exception {
        // Arrange
        when(mockHttpClient.send(any(), any())).thenThrow(new InterruptedException());

        // Act/Assert
        assertThrows(
                CiRetrievalException.class,
                () ->
                        cimitService.fetchContraIndicatorsVc(
                                TEST_USER_ID,
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP,
                                new IpvSessionItem()));
    }

    @Test
    void fetchContraIndicatorsVcVCThrowsExceptionIfHttpRequestThrowsIOException() throws Exception {
        // Arrange
        when(mockHttpClient.send(any(), any())).thenThrow(new IOException());

        // Act/Assert
        assertThrows(
                CiRetrievalException.class,
                () ->
                        cimitService.fetchContraIndicatorsVc(
                                TEST_USER_ID,
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP,
                                new IpvSessionItem()));
    }

    @Test
    void fetchContraIndicatorsVcVcThrowsErrorForInvalidJWT() throws Exception {
        stubFetchPrereqs();
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.OK);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(SUCCESSFUL_GET_CI_HTTP_RESPONSE));
        when(verifiableCredentialValidator.parseAndValidate(
                        any(), any(), any(), any(), any(), eq(false)))
                .thenThrow(
                        new VerifiableCredentialException(
                                500, ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL));

        assertThrows(
                CiRetrievalException.class,
                () ->
                        cimitService.fetchContraIndicatorsVc(
                                TEST_USER_ID,
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP,
                                new IpvSessionItem()));
    }
}
