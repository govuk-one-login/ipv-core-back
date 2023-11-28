package uk.gov.di.ipv.core.callticfcri.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
import uk.gov.di.ipv.core.library.dto.BackEndCriConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.callticfcri.service.TicfCriService.TRUSTMARK;
import static uk.gov.di.ipv.core.callticfcri.service.TicfCriService.X_API_KEY_HEADER;
import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_ADDRESS;

@ExtendWith(MockitoExtension.class)
class TicfCriServiceTest {

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final ClientOAuthSessionItem clientSessionItem =
            ClientOAuthSessionItem.builder()
                    .vtr(List.of("vtr-value"))
                    .userId("a-user-id")
                    .govukSigninJourneyId("a-govuk-journey-id")
                    .build();
    private static final List<String> credentials =
            List.of(M1B_DCMAW_VC, M1A_FRAUD_VC, M1A_ADDRESS_VC);
    // the VC in this response is unimportant as we're mocking the
    // validator - we just need something that can be parsed
    private static final TicfCriDto ticfCriResponse =
            new TicfCriDto(
                    List.of("vtr-value"),
                    "P2",
                    TRUSTMARK,
                    "a-user-id",
                    "a-govuk-journey-id",
                    List.of(VC_ADDRESS));

    private IpvSessionItem ipvSessionItem;
    private BackEndCriConfig ticfCriConfig;

    @Mock private ConfigService mockConfigService;
    @Mock private HttpClient mockHttpClient;
    @Mock private VerifiableCredentialJwtValidator mockVerifiableCredentialJwtValidator;
    @Mock private HttpResponse<String> mockHttpResponse;
    @Captor private ArgumentCaptor<HttpRequest> requestCaptor;
    @InjectMocks private TicfCriService ticfCriService;

    @BeforeEach
    void setUp() throws Exception {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setVot("P2");
        ticfCriConfig =
                new BackEndCriConfig(
                        new URI("https://credential.example.com"),
                        "signing-key",
                        "https://ticf-cri.example.com",
                        false);
    }

    @Test
    void getTicfVcShouldReturnASignedJwtForASuccessfulInvocation() throws Exception {
        BackEndCriConfig ticfConfigWithApiKeyRequired =
                new BackEndCriConfig(
                        new URI("https://credential.example.com"),
                        "signing-key",
                        "https://ticf-cri.example.com",
                        true);
        when(mockConfigService.getBackEndCriConfig(TICF_CRI))
                .thenReturn(ticfConfigWithApiKeyRequired);
        when(mockConfigService.getCriPrivateApiKeyForActiveConnection(TICF_CRI))
                .thenReturn("api-key");
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatus.SC_OK);
        when(mockHttpResponse.body()).thenReturn(objectMapper.writeValueAsString(ticfCriResponse));

        assertEquals(
                VC_ADDRESS,
                ticfCriService
                        .getTicfVc(clientSessionItem, ipvSessionItem, credentials)
                        .get(0)
                        .serialize());

        verify(mockHttpClient).send(requestCaptor.capture(), any());
        assertEquals(
                "api-key", requestCaptor.getValue().headers().firstValue(X_API_KEY_HEADER).get());
    }

    @Test
    void getTicfVcShouldNotIncludeApiKeyIfNotRequired() throws Exception {
        BackEndCriConfig ticfCriConfigWithoutApiKey =
                new BackEndCriConfig(
                        new URI("https://credential.example.com"),
                        "signing-key",
                        "https://ticf-cri.example.com",
                        false);

        when(mockConfigService.getBackEndCriConfig(TICF_CRI))
                .thenReturn(ticfCriConfigWithoutApiKey);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatus.SC_OK);
        when(mockHttpResponse.body()).thenReturn(objectMapper.writeValueAsString(ticfCriResponse));

        ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem, credentials);

        verify(mockHttpClient).send(requestCaptor.capture(), any());

        assertTrue(requestCaptor.getValue().headers().firstValue(X_API_KEY_HEADER).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(ints = {199, 300})
    void getTicfVcShouldReturnEmptyListIfNon200HttpResponse(int statusCode) throws Exception {
        when(mockConfigService.getBackEndCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(statusCode);

        assertEquals(
                List.of(),
                ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem, credentials));
    }

    @Test
    void getTicfVcShouldThrowIfCanNotSerializeRequest() {
        when(mockConfigService.getBackEndCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);

        // Jackson can't serialize mocks
        assertThrows(
                TicfCriServiceException.class,
                () ->
                        ticfCriService.getTicfVc(
                                clientSessionItem, ipvSessionItem, mock(List.class)));
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
        when(mockConfigService.getBackEndCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);
        when(mockHttpClient.send(any(), any()))
                .thenThrow((Throwable) exceptionToThrow.getConstructor().newInstance());

        assertEquals(
                List.of(),
                ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem, credentials));
    }

    @Test
    void getTicfVcShouldThrowIfCanNotParseResponseBody() throws Exception {
        when(mockConfigService.getBackEndCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatus.SC_OK);
        when(mockHttpResponse.body()).thenReturn("🐛");

        assertThrows(
                TicfCriServiceException.class,
                () -> ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem, credentials));
    }

    @Test
    void getTicfVcShouldThrowIfResponseContainsNoCredentials() throws Exception {
        TicfCriDto ticfCriResponseWithoutCreds =
                new TicfCriDto(
                        List.of("vtr-value"),
                        "P2",
                        TRUSTMARK,
                        "a-user-id",
                        "a-govuk-journey-id",
                        List.of());

        when(mockConfigService.getBackEndCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatus.SC_OK);
        when(mockHttpResponse.body())
                .thenReturn(objectMapper.writeValueAsString(ticfCriResponseWithoutCreds));

        TicfCriServiceException thrown =
                assertThrows(
                        TicfCriServiceException.class,
                        () ->
                                ticfCriService.getTicfVc(
                                        clientSessionItem, ipvSessionItem, credentials));

        assertTrue(thrown.getMessage().contains("No credentials in TICF CRI response"));
    }

    @Test
    void getTicfVcShouldThrowIfCredentialReturnedCanNotBeParsed() throws Exception {
        TicfCriDto ticfCriResponseWithoutMangledCred =
                new TicfCriDto(
                        List.of("vtr-value"),
                        "P2",
                        TRUSTMARK,
                        "a-user-id",
                        "a-govuk-journey-id",
                        List.of("🐛"));

        when(mockConfigService.getBackEndCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatus.SC_OK);
        when(mockHttpResponse.body())
                .thenReturn(objectMapper.writeValueAsString(ticfCriResponseWithoutMangledCred));

        assertThrows(
                TicfCriServiceException.class,
                () -> ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem, credentials));
    }

    @Test
    void getTicfVcShouldThrowIfCredentialCanNotBeValidated() throws Exception {
        when(mockConfigService.getBackEndCriConfig(TICF_CRI)).thenReturn(ticfCriConfig);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatus.SC_OK);
        when(mockHttpResponse.body()).thenReturn(objectMapper.writeValueAsString(ticfCriResponse));
        doThrow(VerifiableCredentialException.class)
                .when(mockVerifiableCredentialJwtValidator)
                .validate(any(), any(), any());

        assertThrows(
                TicfCriServiceException.class,
                () -> ticfCriService.getTicfVc(clientSessionItem, ipvSessionItem, credentials));
    }

    private String generateSignedJwt() throws Exception {
        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .issuer("ticf-cri")
                        .subject("a-user-id")
                        .jwtID("a-unique-jwt-id")
                        .notBeforeTime(Date.from(Instant.now()))
                        .expirationTime(Date.from(Instant.now().plusSeconds(60)))
                        .claim("vc", "some-stuff-here")
                        .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        ECDSASigner ecdsaSigner = new ECDSASigner(ECKey.parse(EC_PRIVATE_KEY_JWK));
        signedJWT.sign(ecdsaSigner);
        return signedJWT.serialize();
    }
}
