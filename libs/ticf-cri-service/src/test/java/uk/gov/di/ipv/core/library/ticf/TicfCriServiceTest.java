package uk.gov.di.ipv.core.library.ticf;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.ticf.dto.TicfCriDto;
import uk.gov.di.ipv.core.library.ticf.exception.TicfCriServiceException;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.util.List;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_API_KEY;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.VC_ADDRESS;
import static uk.gov.di.ipv.core.library.ticf.TicfCriService.TRUSTMARK;
import static uk.gov.di.ipv.core.library.ticf.TicfCriService.X_API_KEY_HEADER;

@ExtendWith(MockitoExtension.class)
class TicfCriServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String USER_ID = "a-user-id";
    private static final String SESSION_ID = "session-id";
    private static final List<String> VTR_VALUE = List.of("vtr-value");
    public static final String GOVUK_JOURNEY_ID = "a-govuk-journey-id";
    private static final ClientOAuthSessionItem CLIENT_OAUTH_SESSION_ITEM =
            ClientOAuthSessionItem.builder()
                    .vtr(VTR_VALUE)
                    .userId(USER_ID)
                    .govukSigninJourneyId(GOVUK_JOURNEY_ID)
                    .build();
    // the VC in this response is unimportant as we're mocking the
    // validator - we just need something that can be parsed
    private static final TicfCriDto ticfCriResponse =
            new TicfCriDto(
                    VTR_VALUE,
                    Vot.P2,
                    TRUSTMARK,
                    USER_ID,
                    GOVUK_JOURNEY_ID,
                    List.of(VC_ADDRESS.getVcString()));
    private IpvSessionItem ipvSessionItem;
    private RestCriConfig ticfCriConfig;
    @Mock private ConfigService mockConfigService;
    @Mock private HttpClient mockHttpClient;
    @Mock private VerifiableCredentialValidator mockVerifiableCredentialValidator;
    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @Mock private HttpResponse<String> mockHttpResponse;
    @Captor private ArgumentCaptor<HttpRequest> requestCaptor;
    @Captor private ArgumentCaptor<String> stringCaptor;
    @InjectMocks private TicfCriService ticfCriService;

    @BeforeEach
    void setUp() throws Exception {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setVot(Vot.P2);
        ipvSessionItem.setIpvSessionId(SESSION_ID);
        ticfCriConfig =
                RestCriConfig.builder()
                        .credentialUrl(new URI("https://credential.example.com"))
                        .signingKey(TEST_EC_PUBLIC_JWK)
                        .componentId("https://ticf-cri.example.com")
                        .requiresApiKey(false)
                        .requestTimeout(5L)
                        .build();
    }

    @Test
    void getTicfVcShouldReturnASignedJwtForASuccessfulInvocation() throws Exception {
        RestCriConfig ticfConfigWithApiKeyRequired =
                RestCriConfig.builder()
                        .credentialUrl(new URI("https://credential.example.com"))
                        .signingKey(TEST_EC_PUBLIC_JWK)
                        .componentId("https://ticf-cri.example.com")
                        .requiresApiKey(true)
                        .build();
        when(mockConfigService.getRestCriConfigForConnection(any(), eq(TICF)))
                .thenReturn(ticfConfigWithApiKeyRequired);
        when(mockConfigService.getSecret(CREDENTIAL_ISSUER_API_KEY, TICF.getId(), null))
                .thenReturn("api-key");
        when(mockSessionCredentialsService.getCredentials(SESSION_ID, USER_ID, true))
                .thenReturn(List.of(M1B_DCMAW_VC));
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.OK);
        when(mockHttpResponse.body()).thenReturn(OBJECT_MAPPER.writeValueAsString(ticfCriResponse));
        when(mockVerifiableCredentialValidator.parseAndValidate(any(), any(), any(), any(), any()))
                .thenReturn(List.of(VC_ADDRESS));

        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            var ticfVc = ticfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem);
            assertEquals(VC_ADDRESS.getVcString(), ticfVc.get(0).getVcString());

            mockedBodyPublishers.verify(
                    () -> HttpRequest.BodyPublishers.ofString(stringCaptor.capture()));
            var sentTicfCriDto = OBJECT_MAPPER.readValue(stringCaptor.getValue(), TicfCriDto.class);

            assertEquals(VTR_VALUE, sentTicfCriDto.vtr());
            assertEquals(Vot.P2, sentTicfCriDto.vot());
            assertEquals(TRUSTMARK, sentTicfCriDto.vtm());
            assertEquals(USER_ID, sentTicfCriDto.sub());
            assertEquals(GOVUK_JOURNEY_ID, sentTicfCriDto.govukSigninJourneyId());
            assertEquals(List.of(M1B_DCMAW_VC.getVcString()), sentTicfCriDto.credentials());

            verify(mockHttpClient).send(requestCaptor.capture(), any());
            assertEquals(
                    "api-key",
                    requestCaptor.getValue().headers().firstValue(X_API_KEY_HEADER).get());
        }
    }

    @Test
    void getTicfVcShouldNotIncludeApiKeyIfNotRequired() throws Exception {
        when(mockConfigService.getRestCriConfigForConnection(any(), eq(TICF)))
                .thenReturn(ticfCriConfig);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.OK);
        when(mockHttpResponse.body()).thenReturn(OBJECT_MAPPER.writeValueAsString(ticfCriResponse));

        ticfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem);

        verify(mockHttpClient).send(requestCaptor.capture(), any());

        assertTrue(requestCaptor.getValue().headers().firstValue(X_API_KEY_HEADER).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(ints = {199, 300})
    void getTicfVcShouldReturnEmptyListIfNon200HttpResponse(int statusCode) throws Exception {
        when(mockConfigService.getRestCriConfigForConnection(any(), eq(TICF)))
                .thenReturn(ticfCriConfig);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(statusCode);

        assertEquals(
                List.of(), ticfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem));
    }

    @Test
    void getTicfVcShouldThrowIfErrorFetchingSessionCredentials() throws Exception {
        when(mockSessionCredentialsService.getCredentials(any(), any(), anyBoolean()))
                .thenThrow(
                        new VerifiableCredentialException(
                                SC_SERVER_ERROR, FAILED_TO_GET_CREDENTIAL));

        assertThrows(
                TicfCriServiceException.class,
                () -> ticfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem));
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
        when(mockConfigService.getRestCriConfigForConnection(any(), eq(TICF)))
                .thenReturn(ticfCriConfig);
        when(mockHttpClient.send(any(), any()))
                .thenThrow((Throwable) exceptionToThrow.getConstructor().newInstance());

        assertEquals(
                List.of(), ticfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem));
    }

    @Test
    void getTicfVcShouldThrowIfCanNotParseResponseBody() throws Exception {
        when(mockConfigService.getRestCriConfigForConnection(any(), eq(TICF)))
                .thenReturn(ticfCriConfig);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.OK);
        when(mockHttpResponse.body()).thenReturn("🐛");

        assertThrows(
                TicfCriServiceException.class,
                () -> ticfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem));
    }

    @Test
    void getTicfVcShouldThrowIfResponseContainsEmptyCredentialsList() throws Exception {
        TicfCriDto ticfCriResponseWithoutCreds =
                new TicfCriDto(VTR_VALUE, Vot.P2, TRUSTMARK, USER_ID, GOVUK_JOURNEY_ID, List.of());

        when(mockConfigService.getRestCriConfigForConnection(any(), eq(TICF)))
                .thenReturn(ticfCriConfig);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.OK);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(ticfCriResponseWithoutCreds));

        TicfCriServiceException thrown =
                assertThrows(
                        TicfCriServiceException.class,
                        () -> ticfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem));

        assertTrue(thrown.getMessage().contains("No credentials in TICF CRI response"));
    }

    @Test
    void getTicfVcShouldThrowIfResponseContainsNoCredentials() throws Exception {
        TicfCriDto ticfCriResponseWithoutCreds =
                new TicfCriDto(VTR_VALUE, Vot.P2, TRUSTMARK, USER_ID, GOVUK_JOURNEY_ID, null);

        when(mockConfigService.getRestCriConfigForConnection(any(), eq(TICF)))
                .thenReturn(ticfCriConfig);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.OK);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(ticfCriResponseWithoutCreds));

        TicfCriServiceException thrown =
                assertThrows(
                        TicfCriServiceException.class,
                        () -> ticfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem));

        assertTrue(thrown.getMessage().contains("No credentials in TICF CRI response"));
    }

    @Test
    void getTicfVcShouldThrowIfCredentialReturnedCanNotBeParsed() throws Exception {
        var someCredential = "some credential";
        var ticfResponse = new TicfCriDto(null, null, null, null, null, List.of(someCredential));

        when(mockConfigService.getRestCriConfigForConnection(any(), eq(TICF)))
                .thenReturn(ticfCriConfig);
        when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatusCode.OK);
        when(mockHttpResponse.body()).thenReturn(OBJECT_MAPPER.writeValueAsString(ticfResponse));
        when(mockVerifiableCredentialValidator.parseAndValidate(
                        any(), any(), eq(List.of(someCredential)), any(), any()))
                .thenThrow(
                        new VerifiableCredentialException(
                                500, ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS));

        assertThrows(
                TicfCriServiceException.class,
                () -> ticfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem));
    }

    @Test
    void getTicfVcShouldNotExplodeIfTimeoutIsNull() throws Exception {
        var ticfCriConfigWithZeroTimeout =
                RestCriConfig.builder()
                        .credentialUrl(new URI("https://credential.example.com"))
                        .signingKey(TEST_EC_PUBLIC_JWK)
                        .componentId("https://ticf-cri.example.com")
                        .requiresApiKey(false)
                        .requestTimeout(null)
                        .build();

        when(mockConfigService.getRestCriConfigForConnection(any(), eq(TICF)))
                .thenReturn(ticfCriConfigWithZeroTimeout);
        when(mockHttpClient.<String>send(any(), any()))
                .thenThrow(new HttpTimeoutException("too slow"));

        ticfCriService.getTicfVc(CLIENT_OAUTH_SESSION_ITEM, ipvSessionItem);

        verify(mockHttpClient).send(requestCaptor.capture(), any());
    }
}
