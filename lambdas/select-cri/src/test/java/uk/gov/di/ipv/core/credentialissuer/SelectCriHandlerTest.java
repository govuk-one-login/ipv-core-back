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
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.selectcri.SelectCriHandler;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ADDRESS_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ALLOWED_USER_IDS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ENABLED;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PASSPORT_CRI_ID;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_DCMAW_FAILED_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_FRAUD_VC_PASSED;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_KBV_VC_PASSED;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

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
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @Mock private ClientSessionDetailsDto mockClientSessionDetailsDto;

    private SelectCriHandler underTest;

    @BeforeEach
    void setUp() throws Exception {
        mockConfigurationServiceMethodCalls();

        underTest =
                new SelectCriHandler(
                        mockConfigurationService, mockUserIdentityService, mockIpvSessionService);
    }

    @Test
    void shouldReturnPassportCriJourneyResponse() throws JsonProcessingException {
        mockIpvSessionService();

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/ukPassport", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnAddressCriJourneyResponse() throws JsonProcessingException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        when(mockUserIdentityService.getUserIssuedCredential(userId, CRI_PASSPORT))
                .thenReturn(
                        createUserIssuedCredentialsItem(
                                userId, CRI_PASSPORT, SIGNED_VC_1, LocalDateTime.now()));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/address", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnPyiNoMatchErrorResponseIfAddressCriHasPreviouslyFailed()
            throws JsonProcessingException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, false, "access_denied"));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        when(mockUserIdentityService.getUserIssuedCredential(userId, CRI_PASSPORT))
                .thenReturn(
                        createUserIssuedCredentialsItem(
                                userId, CRI_PASSPORT, SIGNED_VC_1, LocalDateTime.now()));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/pyi-no-match", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnFraudCriJourneyResponse() throws JsonProcessingException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        when(mockUserIdentityService.getUserIssuedCredential(userId, CRI_PASSPORT))
                .thenReturn(
                        createUserIssuedCredentialsItem(
                                userId, CRI_PASSPORT, SIGNED_VC_1, LocalDateTime.now()));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/fraud", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnKBVCriJourneyResponse() throws JsonProcessingException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_FRAUD, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        when(mockUserIdentityService.getUserIssuedCredential(userId, CRI_PASSPORT))
                .thenReturn(
                        createUserIssuedCredentialsItem(
                                userId, CRI_PASSPORT, SIGNED_VC_1, LocalDateTime.now()));

        when(mockUserIdentityService.getUserIssuedCredential(userId, CRI_FRAUD))
                .thenReturn(
                        createUserIssuedCredentialsItem(
                                userId, CRI_FRAUD, SIGNED_FRAUD_VC_PASSED, LocalDateTime.now()));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/kbv", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnJourneyFailedIfAllCriVisited() throws JsonProcessingException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_FRAUD, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_KBV, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        when(mockUserIdentityService.getUserIssuedCredential(userId, CRI_PASSPORT))
                .thenReturn(
                        createUserIssuedCredentialsItem(
                                userId, CRI_PASSPORT, SIGNED_VC_1, LocalDateTime.now()));

        when(mockUserIdentityService.getUserIssuedCredential(userId, CRI_FRAUD))
                .thenReturn(
                        createUserIssuedCredentialsItem(
                                userId, CRI_FRAUD, SIGNED_FRAUD_VC_PASSED, LocalDateTime.now()));

        when(mockUserIdentityService.getUserIssuedCredential(userId, CRI_KBV))
                .thenReturn(
                        createUserIssuedCredentialsItem(
                                userId, CRI_KBV, SIGNED_KBV_VC_PASSED, LocalDateTime.now()));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/fail", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserHasNotVisited() throws JsonProcessingException {
        mockIpvSessionService();

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/dcmaw", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnAddressCriJourneyResponseIfUserHasVisitedDcmawSuccessfully()
            throws JsonProcessingException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(List.of(new VisitedCredentialIssuerDetailsDto("dcmaw", true, null)));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");

        when(mockUserIdentityService.getUserIssuedCredential(anyString(), anyString()))
                .thenReturn(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "dcmaw", SIGNED_DCMAW_VC, LocalDateTime.now()));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/address", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnFraudCriJourneyResponseIfUserHasVisitedDcmawAndAddressSuccessfully()
            throws JsonProcessingException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(CRI_DCMAW, true, null),
                                new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null)));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");

        when(mockUserIdentityService.getUserIssuedCredential("test-user-id", CRI_DCMAW))
                .thenReturn(
                        createUserIssuedCredentialsItem(
                                "test-user-id", "dcmaw", SIGNED_DCMAW_VC, LocalDateTime.now()));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/fraud", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnPyiNoMatchJourneyResponseIfUserHasVisitedDcmawAndAddressAndFraudSuccessfully()
            throws JsonProcessingException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(CRI_DCMAW, true, null),
                                new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null),
                                new VisitedCredentialIssuerDetailsDto(CRI_FRAUD, true, null)));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");

        when(mockUserIdentityService.getUserIssuedCredential(userId, CRI_DCMAW))
                .thenReturn(
                        createUserIssuedCredentialsItem(
                                userId, CRI_DCMAW, SIGNED_DCMAW_VC, LocalDateTime.now()));

        when(mockUserIdentityService.getUserIssuedCredential(userId, CRI_FRAUD))
                .thenReturn(
                        createUserIssuedCredentialsItem(
                                userId, CRI_FRAUD, SIGNED_FRAUD_VC_PASSED, LocalDateTime.now()));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/fail", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserHasVisitedDcmawButItFailedWithAVc()
            throws JsonProcessingException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(List.of(new VisitedCredentialIssuerDetailsDto("dcmaw", true, null)));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");

        when(mockUserIdentityService.getUserIssuedCredential(anyString(), anyString()))
                .thenReturn(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "dcmaw", SIGNED_DCMAW_FAILED_VC, LocalDateTime.now()));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/ukPassport", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserHasVisitedDcmawButItFailedWithoutAVc()
            throws JsonProcessingException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(
                                        "dcmaw", false, "access_denied")));

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/ukPassport", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserIsIncludedInAllowedList()
            throws JsonProcessingException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_ALLOWED_USER_IDS))
                .thenReturn("test-user-id,test-user-id-2,test-user-id-3");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/dcmaw", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserIsNotIncludedInAllowedList()
            throws JsonProcessingException {
        mockIpvSessionService();

        String userId = "test-user-id-4";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_ALLOWED_USER_IDS))
                .thenReturn("test-user-id,test-user-id-2,test-user-id-3");

        APIGatewayProxyRequestEvent input = createRequestEvent();

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> responseBody = getResponseBodyAsMap(response);

        assertEquals("/journey/ukPassport", responseBody.get("journey"));
        assertEquals(HTTPResponse.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfAllowedUserIdListIsEmpty()
            throws JsonProcessingException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigurationService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigurationService.getSsmParameter(DCMAW_ALLOWED_USER_IDS)).thenReturn("");

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
