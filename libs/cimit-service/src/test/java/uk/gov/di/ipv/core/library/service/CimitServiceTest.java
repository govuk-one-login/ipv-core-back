package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
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
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.io.IOException;
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
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CIMIT_API_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.service.CimitService.FAILED_RESPONSE;
import static uk.gov.di.ipv.core.library.service.CimitService.IP_ADDRESS_HEADER;
import static uk.gov.di.ipv.core.library.service.CimitService.X_API_KEY_HEADER;

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
    @Mock private VerifiableCredentialValidator verifiableCredentialValidator;
    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<String> mockHttpResponse;
    @Mock private IpvSessionService ipvSessionService;
    @InjectMocks CimitService cimitService;

    @Test
    void submitVcSendsHttpRequestToApi() throws Exception {
        // Arrange
        when(configService.getParameter(ConfigurationVariable.CIMIT_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getSecret(CIMIT_API_KEY)).thenReturn(MOCK_CIMIT_API_KEY);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(SUCCESSFUL_POST_HTTP_RESPONSE));

        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            cimitService.submitVC(
                    PASSPORT_NON_DCMAW_SUCCESSFUL_VC, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);

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
        when(configService.getParameter(ConfigurationVariable.CIMIT_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getSecret(CIMIT_API_KEY)).thenReturn(MOCK_CIMIT_API_KEY);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(FAILED_CIMIT_HTTP_RESPONSE));

        // Act/Assert
        assertThrows(
                CiPutException.class,
                () ->
                        cimitService.submitVC(
                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP));
    }

    @Test
    void submitMitigationVCListSendsHttpRequestToApi() throws Exception {
        when(configService.getParameter(ConfigurationVariable.CIMIT_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getSecret(CIMIT_API_KEY)).thenReturn(MOCK_CIMIT_API_KEY);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(SUCCESSFUL_POST_HTTP_RESPONSE));

        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);
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
        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);

        when(configService.getParameter(ConfigurationVariable.CIMIT_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getSecret(CIMIT_API_KEY)).thenReturn(MOCK_CIMIT_API_KEY);
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

    private static Stream<Arguments> provideArgumentsForGetContraIndicatorsVc() throws Exception {
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
    @MethodSource("provideArgumentsForGetContraIndicatorsVc")
    void sendsHttpRequestToCimitApiAndStoresInSession(
            IpvSessionItem ipvSessionItem,
            VerifiableCredential vcFromCimit,
            String expectedStoredVc,
            boolean hasSecurityCheckCredentialBeenUpdated)
            throws Exception {
        // Arrange
        when(configService.getParameter(ConfigurationVariable.CIMIT_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getSecret(CIMIT_API_KEY)).thenReturn(MOCK_CIMIT_API_KEY);
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
        when(configService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(TEST_EC_PUBLIC_JWK);

        // Act
        cimitService.getContraIndicatorsVc(
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
    void getContraIndicatorsVcVCThrowsExceptionIfHttpRequestReturnsFailedResponse()
            throws Exception {
        // Arrange
        when(configService.getParameter(ConfigurationVariable.CIMIT_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getSecret(CIMIT_API_KEY)).thenReturn(MOCK_CIMIT_API_KEY);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.INTERNAL_SERVER_ERROR);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(FAILED_CIMIT_HTTP_RESPONSE));

        // Act/Assert
        assertThrows(
                CiRetrievalException.class,
                () ->
                        cimitService.getContraIndicatorsVc(
                                TEST_USER_ID,
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP,
                                new IpvSessionItem()));
    }

    @Test
    void getContraIndicatorsVcVCThrowsExceptionIfHttpRequestIsInterrupted() throws Exception {
        // Arrange
        when(configService.getParameter(ConfigurationVariable.CIMIT_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getSecret(CIMIT_API_KEY)).thenReturn(MOCK_CIMIT_API_KEY);
        when(mockHttpClient.send(any(), any())).thenThrow(new InterruptedException());

        // Act/Assert
        assertThrows(
                CiRetrievalException.class,
                () ->
                        cimitService.getContraIndicatorsVc(
                                TEST_USER_ID,
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP,
                                new IpvSessionItem()));
    }

    @Test
    void getContraIndicatorsVcVCThrowsExceptionIfHttpRequestThrowsIOException() throws Exception {
        // Arrange
        when(configService.getParameter(ConfigurationVariable.CIMIT_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getSecret(CIMIT_API_KEY)).thenReturn(MOCK_CIMIT_API_KEY);
        when(mockHttpClient.send(any(), any())).thenThrow(new IOException());

        // Act/Assert
        assertThrows(
                CiRetrievalException.class,
                () ->
                        cimitService.getContraIndicatorsVc(
                                TEST_USER_ID,
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP,
                                new IpvSessionItem()));
    }

    @Test
    void getContraIndicatorsVcVcThrowsErrorForInvalidJWT() throws Exception {
        when(configService.getParameter(ConfigurationVariable.CIMIT_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getSecret(CIMIT_API_KEY)).thenReturn(MOCK_CIMIT_API_KEY);
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
                        cimitService.getContraIndicatorsVc(
                                TEST_USER_ID,
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP,
                                new IpvSessionItem()));
    }
}
