package uk.gov.di.ipv.core.credentialissuer;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.selectcri.SelectCriHandler;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ADDRESS_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ALLOWED_USER_IDS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ENABLED;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_SHOULD_SEND_ALL_USERS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PASSPORT_CRI_ID;
import static uk.gov.di.ipv.core.selectcri.SelectCriHandler.APP_JOURNEY_USER_ID_PREFIX;

@ExtendWith(MockitoExtension.class)
class SelectCriHandlerTest {

    public static final String TEST_SESSION_ID = "the-session-id";
    public static final String TEST_USER_ID = "test-user-id";
    public static final String CRI_PASSPORT = "ukPassport";
    public static final String CRI_FRAUD = "fraud";
    public static final String CRI_KBV = "kbv";
    public static final String CRI_ADDRESS = "address";
    public static final String CRI_DCMAW = "dcmaw";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock private Context context;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @Mock private ClientSessionDetailsDto mockClientSessionDetailsDto;

    private SelectCriHandler underTest;

    @BeforeEach
    void setUp() throws Exception {
        mockConfigurationServiceMethodCalls();

        underTest = new SelectCriHandler(mockConfigurationService, mockIpvSessionService);
    }

    @Test
    void shouldReturnPassportCriJourneyResponse()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        when(mockConfigurationService.getCredentialIssuer(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-dcmaw-iss"));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/ukPassport", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnAddressCriJourneyResponse()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);
        when(mockConfigurationService.getCredentialIssuer(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss"));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/address", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnPyiNoMatchErrorResponseIfAddressCriHasPreviouslyFailed()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);
        when(mockConfigurationService.getCredentialIssuer(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss"));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, false, "access_denied"));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/pyi-no-match", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnFraudCriJourneyResponse() throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);
        when(mockConfigurationService.getCredentialIssuer(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss"));
        when(mockConfigurationService.getCredentialIssuer(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss"));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/fraud", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnKBVCriJourneyResponse() throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);
        when(mockConfigurationService.getCredentialIssuer(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss"));
        when(mockConfigurationService.getCredentialIssuer(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss"));
        when(mockConfigurationService.getCredentialIssuer(CRI_KBV))
                .thenReturn(createCriConfig(CRI_KBV, "test-kbv-iss"));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_FRAUD, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/kbv", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnJourneyFailedIfAllCriVisited()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);
        when(mockConfigurationService.getCredentialIssuer(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss"));
        when(mockConfigurationService.getCredentialIssuer(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss"));
        when(mockConfigurationService.getCredentialIssuer(CRI_KBV))
                .thenReturn(createCriConfig(CRI_KBV, "test-kbv-iss"));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_FRAUD, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_KBV, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/fail", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserHasNotVisited()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigurationService.getCredentialIssuer(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss"));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn("true");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/dcmaw", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnDcmawSuccessJourneyResponseIfUserHasVisitedDcmawSuccessfully()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");
        when(mockConfigurationService.getCredentialIssuer(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss"));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-dcmaw-iss", true)));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(List.of(new VisitedCredentialIssuerDetailsDto("dcmaw", true, null)));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn("true");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/dcmaw-success", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnFraudCriJourneyResponseIfUserHasVisitedDcmawAndAddressSuccessfully()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");

        when(mockConfigurationService.getCredentialIssuer(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss"));
        when(mockConfigurationService.getCredentialIssuer(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss"));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-dcmaw-iss", true)));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(CRI_DCMAW, true, null),
                                new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null)));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn("true");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/fraud", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnPyiNoMatchJourneyResponseIfUserHasVisitedDcmawAndAddressAndFraudSuccessfully()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);
        when(mockConfigurationService.getCredentialIssuer(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss"));
        when(mockConfigurationService.getCredentialIssuer(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss"));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto("test-dcmaw-iss", true),
                                new VcStatusDto("test-fraud-iss", true)));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(CRI_DCMAW, true, null),
                                new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null),
                                new VisitedCredentialIssuerDetailsDto(CRI_FRAUD, true, null)));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto("test-dcmaw-iss", true),
                                new VcStatusDto("test-address-iss", true),
                                new VcStatusDto("test-fraud-iss", true)));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn("true");

        when(mockConfigurationService.getCredentialIssuer(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss"));
        when(mockConfigurationService.getCredentialIssuer(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss"));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/fail", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserHasVisitedDcmawButItFailedWithAVc()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");
        when(mockConfigurationService.getCredentialIssuer(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss"));
        when(mockConfigurationService.getCredentialIssuer(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss"));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(List.of(new VisitedCredentialIssuerDetailsDto("dcmaw", true, null)));
        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn("true");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/ukPassport", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserHasVisitedDcmawButItFailedWithoutAVc()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");
        when(mockConfigurationService.getCredentialIssuer(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss"));
        when(mockConfigurationService.getCredentialIssuer(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss"));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(
                                        "dcmaw", false, "access_denied")));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn("true");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/ukPassport", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnPyiNoMatchErrorJourneyResponseIfUserHasAPreviouslyFailedVisitToAddress()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");
        when(mockConfigurationService.getCredentialIssuer(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss"));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto("dcmaw", true, null),
                                new VisitedCredentialIssuerDetailsDto(
                                        "address", false, "access_denied")));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-dcmaw-iss", true)));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn("true");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/pyi-no-match", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnKbvFailErrorJourneyResponseIfUserHasAPreviouslyFailedVisitKbv()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");
        when(mockConfigurationService.getCredentialIssuer(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss"));
        when(mockConfigurationService.getCredentialIssuer(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss"));
        when(mockConfigurationService.getCredentialIssuer(CRI_KBV))
                .thenReturn(createCriConfig(CRI_KBV, "test-kbv-iss"));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto("ukPassport", true, null),
                                new VisitedCredentialIssuerDetailsDto("address", true, null),
                                new VisitedCredentialIssuerDetailsDto("fraud", true, null),
                                new VisitedCredentialIssuerDetailsDto(
                                        "kbv", false, "access_denied")));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto("test-passport-iss", true),
                                new VcStatusDto("test-fraud-iss", true),
                                new VcStatusDto("test-kbv-iss", false)));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("false");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/pyi-kbv-fail", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnCorrectJourneyResponseWhenVcStatusesAreNull()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");
        when(mockConfigurationService.getCredentialIssuer(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss"));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());
        when(mockIpvSessionItem.getCurrentVcStatuses()).thenReturn(null);

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("false");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/ukPassport", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserIsIncludedInAllowedList()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        when(mockConfigurationService.getCredentialIssuer(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss"));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn("false");
        when(mockConfigurationService.getSsmParameter(DCMAW_ALLOWED_USER_IDS))
                .thenReturn("test-user-id,test-user-id-2,test-user-id-3");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/dcmaw", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserIdHasAppJourneyPrefix()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        String userId = APP_JOURNEY_USER_ID_PREFIX + "some-uuid";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        when(mockConfigurationService.getCredentialIssuer(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss"));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn("false");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/dcmaw", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserIsNotIncludedInAllowedList()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id-4";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigurationService.getCredentialIssuer(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss"));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn("false");
        when(mockConfigurationService.getSsmParameter(DCMAW_ALLOWED_USER_IDS))
                .thenReturn("test-user-id,test-user-id-2,test-user-id-3");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/ukPassport", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfShouldSendAllUsersToAppVarIsTrue()
            throws JsonProcessingException, URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigurationService.getCredentialIssuer(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss"));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn(String.valueOf(true));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/dcmaw", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    private void mockIpvSessionService() {
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(mockClientSessionDetailsDto);
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(mockIpvSessionItem);
    }

    private void mockConfigurationServiceMethodCalls() {
        when(mockConfigurationService.getSsmParameter(PASSPORT_CRI_ID)).thenReturn(CRI_PASSPORT);
        when(mockConfigurationService.getSsmParameter(FRAUD_CRI_ID)).thenReturn(CRI_FRAUD);
        when(mockConfigurationService.getSsmParameter(KBV_CRI_ID)).thenReturn(CRI_KBV);
        when(mockConfigurationService.getSsmParameter(ADDRESS_CRI_ID)).thenReturn(CRI_ADDRESS);
        when(mockConfigurationService.getSsmParameter(DCMAW_CRI_ID)).thenReturn(CRI_DCMAW);
        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("false");
    }

    private APIGatewayProxyRequestEvent createRequestEvent() {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", TEST_SESSION_ID));
        return input;
    }

    private Map<String, String> getResponseBodyAsMap(APIGatewayProxyResponseEvent response)
            throws JsonProcessingException {
        return objectMapper.readValue(response.getBody(), Map.class);
    }

    private CredentialIssuerConfig createCriConfig(String criId, String criIss)
            throws URISyntaxException {
        return new CredentialIssuerConfig(
                criId,
                criId,
                new URI("http://example.com/token"),
                new URI("http://example.com/credential"),
                new URI("http://example.com/authorize"),
                "ipv-core",
                "test-jwk",
                "test-jwk",
                criIss,
                new URI("http://example.com/redirect"));
    }

    private UserIssuedCredentialsItem createUserIssuedCredentialsItem(
            String userId, String credentialIssuer, String credential, LocalDateTime dateCreated) {
        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setUserId(userId);
        userIssuedCredentialsItem.setCredentialIssuer(credentialIssuer);
        userIssuedCredentialsItem.setCredential(credential);
        userIssuedCredentialsItem.setDateCreated(dateCreated);
        return userIssuedCredentialsItem;
    }
}
