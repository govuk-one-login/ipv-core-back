package uk.gov.di.ipv.core.callticfcri.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.callticfcri.dto.TicfCriDto;
import uk.gov.di.ipv.core.callticfcri.exception.TicfCriServiceException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.callticfcri.service.TicfCriService.TRUSTMARK;
import static uk.gov.di.ipv.core.callticfcri.service.TicfCriService.X_API_KEY_HEADER;
import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.VC_ADDRESS;

@ExtendWith(MockitoExtension.class)
class TicfCriServiceTest {
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final ClientOAuthSessionItem clientSessionItem =
            ClientOAuthSessionItem.builder()
                    .vtr(List.of("vtr-value"))
                    .userId("a-user-id")
                    .govukSigninJourneyId("a-govuk-journey-id")
                    .build();
    private static List<String> vcsReceivedThisSession;
    // the VC in this response is unimportant as we're mocking the
    // validator - we just need something that can be parsed
    private static final TicfCriDto ticfCriResponse =
            new TicfCriDto(
                    List.of("vtr-value"),
                    Vot.P2,
                    TRUSTMARK,
                    "a-user-id",
                    "a-govuk-journey-id",
                    List.of(VC_ADDRESS.getVcString()));
    private IpvSessionItem ipvSessionItem;
    private RestCriConfig ticfCriConfig;
    @Mock private ConfigService mockConfigService;
    @Mock private HttpClient mockHttpClient;
    @Mock private VerifiableCredentialValidator mockVerifiableCredentialValidator;
    @Mock private HttpResponse<String> mockHttpResponse;
    @Captor private ArgumentCaptor<HttpRequest> requestCaptor;
    @InjectMocks private TicfCriService ticfCriService;

    @BeforeEach
    void setUp() throws Exception {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setVot(Vot.P2);
        ticfCriConfig =
                RestCriConfig.builder()
                        .credentialUrl(new URI("https://credential.example.com"))
                        .signingKey(EC_PUBLIC_JWK)
                        .componentId("https://ticf-cri.example.com")
                        .requiresApiKey(false)
                        .build();
        vcsReceivedThisSession =
                List.of(
                        M1B_DCMAW_VC.getVcString(),
                        M1A_ADDRESS_VC.getVcString(),
                        M1A_EXPERIAN_FRAUD_VC.getVcString());
    }

    @Test
    void getTicfVcShouldReturnASignedJwtForASuccessfulInvocation() throws Exception {
        RestCriConfig ticfConfigWithApiKeyRequired =
                RestCriConfig.builder()
                        .credentialUrl(new URI("https://credential.example.com"))
                        .signingKey(EC_PUBLIC_JWK)
                        .componentId("https://ticf-cri.example.com")
                        .requiresApiKey(true)
                        .build();
        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(ticfConfigWithApiKeyRequired);
        when(mockConfigService.getCriPrivateApiKeyForActiveConnection(TICF_CRI))
                .thenReturn("api-key");
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatus.SC_OK);
        when(mockHttpResponse.body()).thenReturn(objectMapper.writeValueAsString(ticfCriResponse));
        when(mockVerifiableCredentialValidator.parseAndValidate(
                        any(), any(), any(), any(), any(), any()))
                .thenReturn(List.of(VC_ADDRESS));

        assertEquals(
                VC_ADDRESS.getVcString(),
                ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem).get(0).getVcString());

        verify(mockHttpClient).send(requestCaptor.capture(), any());
        assertEquals(
                "api-key", requestCaptor.getValue().headers().firstValue(X_API_KEY_HEADER).get());
    }

    @Test
    void getTicfVcShouldNotIncludeApiKeyIfNotRequired() throws Exception {
        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatus.SC_OK);
        when(mockHttpResponse.body()).thenReturn(objectMapper.writeValueAsString(ticfCriResponse));

        ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem);

        verify(mockHttpClient).send(requestCaptor.capture(), any());

        assertTrue(requestCaptor.getValue().headers().firstValue(X_API_KEY_HEADER).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(ints = {199, 300})
    void getTicfVcShouldReturnEmptyListIfNon200HttpResponse(int statusCode) throws Exception {
        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(statusCode);

        assertEquals(List.of(), ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem));
    }

    @Test
    void getTicfVcShouldThrowIfCanNotSerializeRequest() {
        ipvSessionItem.setVcReceivedThisSession(mock(List.class));
        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);
        // Jackson can't serialize mocks
        assertThrows(
                TicfCriServiceException.class,
                () -> ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem));
    }

    @ParameterizedTest
    @ValueSource(
            classes = {
                IOException.class,
                InterruptedException.class,
                IllegalArgumentException.class,
                SecurityException.class
            })
    void getTicfVcShouldReturnEmptyListIfHttpClientEncountersException(Class<?> exceptionToThrow)
            throws Exception {
        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);
        when(mockHttpClient.send(any(), any()))
                .thenThrow((Throwable) exceptionToThrow.getConstructor().newInstance());

        assertEquals(List.of(), ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem));
    }

    @Test
    void getTicfVcShouldThrowIfCanNotParseResponseBody() throws Exception {
        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatus.SC_OK);
        when(mockHttpResponse.body()).thenReturn("🐛");

        assertThrows(
                TicfCriServiceException.class,
                () -> ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem));
    }

    @Test
    void getTicfVcShouldThrowIfResponseContainsNoCredentials() throws Exception {
        TicfCriDto ticfCriResponseWithoutCreds =
                new TicfCriDto(
                        List.of("vtr-value"),
                        Vot.P2,
                        TRUSTMARK,
                        "a-user-id",
                        "a-govuk-journey-id",
                        List.of());

        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatus.SC_OK);
        when(mockHttpResponse.body())
                .thenReturn(objectMapper.writeValueAsString(ticfCriResponseWithoutCreds));

        TicfCriServiceException thrown =
                assertThrows(
                        TicfCriServiceException.class,
                        () -> ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem));

        assertTrue(thrown.getMessage().contains("No credentials in TICF CRI response"));
    }

    @Test
    void getTicfVcShouldThrowIfCredentialReturnedCanNotBeParsed() throws Exception {
        var someCredential = "some credential";
        var ticfResponse = new TicfCriDto(null, null, null, null, null, List.of(someCredential));

        when(mockConfigService.getRestCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatus.SC_OK);
        when(mockHttpResponse.body()).thenReturn(objectMapper.writeValueAsString(ticfResponse));
        when(mockVerifiableCredentialValidator.parseAndValidate(
                        any(), any(), eq(List.of(someCredential)), any(), any(), any()))
                .thenThrow(
                        new VerifiableCredentialException(
                                500, ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS));

        assertThrows(
                TicfCriServiceException.class,
                () -> ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem));
    }
}
