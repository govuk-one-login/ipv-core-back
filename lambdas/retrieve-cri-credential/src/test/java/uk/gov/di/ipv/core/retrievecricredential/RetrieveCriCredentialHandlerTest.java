package uk.gov.di.ipv.core.retrievecricredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.CiPutException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.CredentialIssuerService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.VerifiableCredentialJwtValidator;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.AUDIENCE_FOR_CLIENTS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRACT_INDICATORS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

@ExtendWith(MockitoExtension.class)
class RetrieveCriCredentialHandlerTest {
    public static final String ACCESS_TOKEN = "Bearer dGVzdAo=";
    public static final String CREDENTIAL_ISSUER_ID = "PassportIssuer";
    public static final String TEST_USER_ID = "test-user-id";
    public static final String TEST_STATE = "test-state";

    @Mock private Context context;
    @Mock private CredentialIssuerService credentialIssuerService;
    @Mock private AuditService auditService;
    @Mock private static ConfigurationService configurationService;
    @Mock private VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private IpvSessionItem ipvSessionItem;
    @Mock private CiStorageService ciStorageService;
    @InjectMocks private RetrieveCriCredentialHandler handler;

    private static ClientSessionDetailsDto testClientSessionDetailsDto;
    private static BearerAccessToken testBearerAccessToken;
    private static CredentialIssuerConfig testPassportIssuer;
    private static APIGatewayProxyRequestEvent testInputEvent;
    private static final String testSessionId = SecureTokenHelper.generate();
    private static final String testApiKey = "test-api-key";
    private static final String testComponentId = "https://ipv-core-test.example.com";

    @BeforeAll
    static void setUp() throws URISyntaxException, com.nimbusds.oauth2.sdk.ParseException {
        testPassportIssuer =
                new CredentialIssuerConfig(
                        CREDENTIAL_ISSUER_ID,
                        "any",
                        new URI("https://www.example.com"),
                        new URI("https://www.example.com/credential"),
                        new URI("https://www.example.com/authorize"),
                        "ipv-core",
                        "{}",
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "test-audience",
                        new URI("https://www.example.com/credential-issuers/callback/criId"));

        testClientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "code",
                        "test-client-id",
                        "https://example.com/redirect",
                        TEST_STATE,
                        TEST_USER_ID,
                        "test-journey-id",
                        false);

        testBearerAccessToken = BearerAccessToken.parse(ACCESS_TOKEN);

        testInputEvent =
                createRequestEvent(
                        Map.of(
                                "access_token",
                                ACCESS_TOKEN,
                                "credential_issuer_id",
                                CREDENTIAL_ISSUER_ID),
                        Map.of("ipv-session-id", testSessionId));
    }

    @Test
    void shouldReceive200AndJourneyResponseOnSuccessfulRequest() throws Exception {
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(ipvSessionItem.getClientSessionDetails()).thenReturn(testClientSessionDetailsDto);
        when(ipvSessionItem.getCredentialIssuerSessionDetails())
                .thenReturn(new CredentialIssuerSessionDetailsDto());

        when(credentialIssuerService.getVerifiableCredential(
                        testBearerAccessToken, testPassportIssuer, testApiKey))
                .thenReturn(List.of(SignedJWT.parse(SIGNED_VC_1)));

        mockServiceCallsAndSessionItem();

        APIGatewayProxyResponseEvent response = handler.handleRequest(testInputEvent, context);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(AuditEventTypes.IPV_VC_RECEIVED, auditEvents.get(0).getEventName());

        verify(verifiableCredentialJwtValidator)
                .validate(any(SignedJWT.class), eq(testPassportIssuer), eq(TEST_USER_ID));

        Integer statusCode = response.getStatusCode();
        Map<String, String> responseBody = getResponseBodyAsMap(response);
        assertEquals(HTTPResponse.SC_OK, statusCode);
        assertEquals("/journey/next", responseBody.get("journey"));
    }

    @Test
    void shouldReturn500ErrorJourneyResponseIfMissingIpvSessionIdHeader()
            throws JsonProcessingException {
        APIGatewayProxyRequestEvent input =
                createRequestEvent(Collections.emptyMap(), Collections.emptyMap());
        APIGatewayProxyResponseEvent response = handler.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals(HTTPResponse.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                String.valueOf(ErrorResponse.MISSING_IPV_SESSION_ID.getCode()),
                String.valueOf(responseBody.get("error")));
    }

    @Test
    void shouldReturn200ErrorJourneyResponseIfCredentialIssuerServiceGetCredentialThrows()
            throws JsonProcessingException {
        mockServiceCallsAndSessionItem();

        when(credentialIssuerService.getVerifiableCredential(any(), any(), anyString()))
                .thenThrow(
                        new CredentialIssuerException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER));

        APIGatewayProxyResponseEvent response = handler.handleRequest(testInputEvent, context);

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
        assertEquals("/journey/error", getResponseBodyAsMap(response).get("journey"));
    }

    @Test
    void shouldReceive200ErrorJourneyResponseIfSqsExceptionIsThrown()
            throws JsonProcessingException, SqsException, ParseException {
        mockServiceCallsAndSessionItem();
        when(credentialIssuerService.getVerifiableCredential(
                        testBearerAccessToken, testPassportIssuer, testApiKey))
                .thenReturn(List.of(SignedJWT.parse(SIGNED_VC_1)));

        doThrow(new SqsException("Test sqs error"))
                .when(auditService)
                .sendAuditEvent(any(AuditEvent.class));

        APIGatewayProxyResponseEvent response = handler.handleRequest(testInputEvent, context);

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
        assertEquals("/journey/error", getResponseBodyAsMap(response).get("journey"));
    }

    @Test
    void shouldReturn200ErrorJourneyIfVCFailsValidation() throws Exception {
        when(credentialIssuerService.getVerifiableCredential(
                        testBearerAccessToken, testPassportIssuer, testApiKey))
                .thenReturn(List.of(SignedJWT.parse(SIGNED_VC_1)));

        mockServiceCallsAndSessionItem();

        doThrow(
                        new CredentialIssuerException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL))
                .when(verifiableCredentialJwtValidator)
                .validate(any(), any(), any());

        APIGatewayProxyResponseEvent response = handler.handleRequest(testInputEvent, context);

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
        assertEquals("/journey/error", getResponseBodyAsMap(response).get("journey"));
    }

    @Test
    void shouldReceive200ResponseCodeAndSendIpvVcReceivedAuditEvent() throws Exception {
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(ipvSessionItem.getClientSessionDetails()).thenReturn(testClientSessionDetailsDto);
        when(credentialIssuerService.getVerifiableCredential(
                        testBearerAccessToken, testPassportIssuer, testApiKey))
                .thenReturn(List.of(SignedJWT.parse(SIGNED_CONTRACT_INDICATORS)));
        mockServiceCallsAndSessionItem();

        APIGatewayProxyResponseEvent response = handler.handleRequest(testInputEvent, context);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(AuditEventTypes.IPV_VC_RECEIVED, auditEvents.get(0).getEventName());

        assertEquals(testComponentId, auditEvents.get(0).getComponentId());
        AuditEventUser auditEventUser = auditEvents.get(0).getUser();
        assertEquals(TEST_USER_ID, auditEventUser.getUserId());
        assertEquals(testSessionId, auditEventUser.getSessionId());

        AuditExtensionsVcEvidence auditExtensionsVcEvidence =
                (AuditExtensionsVcEvidence) auditEvents.get(0).getExtensions();
        assertEquals("https://issuer.example.com", auditExtensionsVcEvidence.getIss());
        JsonNode evidenceItem = auditExtensionsVcEvidence.getEvidence().get(0);
        assertEquals("IdentityCheck", evidenceItem.get("type").asText());
        assertEquals("DSJJSEE29392", evidenceItem.get("txn").asText());
        assertEquals("0", evidenceItem.get("verificationScore").asText());
        assertEquals("[ \"A02\", \"A03\" ]", evidenceItem.get("ci").toPrettyString());

        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReceive200ResponseCodeAndSendIpvVcReceivedAuditEventWhenVcEvidenceIsMissing()
            throws Exception {
        when(credentialIssuerService.getVerifiableCredential(
                        testBearerAccessToken, testPassportIssuer, testApiKey))
                .thenReturn(List.of(SignedJWT.parse(SIGNED_ADDRESS_VC)));
        mockServiceCallsAndSessionItem();

        APIGatewayProxyResponseEvent response = handler.handleRequest(testInputEvent, context);

        ArgumentCaptor<AuditEvent> argumentCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(argumentCaptor.capture());
        AuditEvent event = argumentCaptor.getAllValues().get(0);
        assertEquals(AuditEventTypes.IPV_VC_RECEIVED, event.getEventName());

        assertEquals(testComponentId, event.getComponentId());

        AuditEventUser auditEventUser = event.getUser();
        assertEquals(TEST_USER_ID, auditEventUser.getUserId());
        assertEquals(testSessionId, auditEventUser.getSessionId());

        AuditExtensionsVcEvidence auditExtensionsVcEvidence =
                (AuditExtensionsVcEvidence) argumentCaptor.getValue().getExtensions();
        assertEquals(
                "https://staging-di-ipv-cri-address-front.london.cloudapps.digital",
                auditExtensionsVcEvidence.getIss());
        assertNull(auditExtensionsVcEvidence.getEvidence());
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldNotStoreVcIfFailedToSubmitItToTheCiStorageSystem() throws Exception {
        when(credentialIssuerService.getVerifiableCredential(
                        testBearerAccessToken, testPassportIssuer, testApiKey))
                .thenReturn(List.of(SignedJWT.parse(SIGNED_ADDRESS_VC)));
        when(configurationService.getCredentialIssuer(CREDENTIAL_ISSUER_ID))
                .thenReturn(testPassportIssuer);
        when(configurationService.getSsmParameter(AUDIENCE_FOR_CLIENTS))
                .thenReturn(testComponentId);
        when(configurationService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setClientSessionDetails(testClientSessionDetailsDto);
        ipvSessionItem.setCredentialIssuerSessionDetails(
                new CredentialIssuerSessionDetailsDto(
                        CREDENTIAL_ISSUER_ID, TEST_STATE, ACCESS_TOKEN));
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        doThrow(new CiPutException("Lambda execution failed"))
                .when(ciStorageService)
                .submitVC(any(SignedJWT.class), anyString());

        APIGatewayProxyResponseEvent response = handler.handleRequest(testInputEvent, context);

        verify(credentialIssuerService, never()).persistUserCredentials(any(), any(), any());

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        var updatedIpvSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertEquals(1, updatedIpvSessionItem.getVisitedCredentialIssuerDetails().size());
        assertEquals(
                CREDENTIAL_ISSUER_ID,
                updatedIpvSessionItem.getVisitedCredentialIssuerDetails().get(0).getCriId());
        assertFalse(
                updatedIpvSessionItem
                        .getVisitedCredentialIssuerDetails()
                        .get(0)
                        .isReturnedWithVc());
        assertEquals(
                OAuth2Error.SERVER_ERROR_CODE,
                updatedIpvSessionItem.getVisitedCredentialIssuerDetails().get(0).getOauthError());
    }

    private void mockServiceCallsAndSessionItem() {
        when(configurationService.getCredentialIssuer(CREDENTIAL_ISSUER_ID))
                .thenReturn(testPassportIssuer);
        when(configurationService.getSsmParameter(AUDIENCE_FOR_CLIENTS))
                .thenReturn(testComponentId);
        when(configurationService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(ipvSessionItem.getClientSessionDetails()).thenReturn(testClientSessionDetailsDto);
        when(ipvSessionItem.getCredentialIssuerSessionDetails())
                .thenReturn(
                        new CredentialIssuerSessionDetailsDto(
                                CREDENTIAL_ISSUER_ID, TEST_STATE, ACCESS_TOKEN));
        when(ipvSessionItem.getIpvSessionId()).thenReturn(testSessionId);
    }

    private Map<String, String> getResponseBodyAsMap(APIGatewayProxyResponseEvent response)
            throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(response.getBody(), new TypeReference<>() {});
    }

    private static APIGatewayProxyRequestEvent createRequestEvent(
            Map<String, String> body, Map<String, String> headers) {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setBody(
                body.keySet().stream()
                        .map(key -> key + "=" + body.get(key))
                        .collect(Collectors.joining("&")));
        input.setHeaders(headers);
        return input;
    }
}
