package uk.gov.di.ipv.core.buildprovenuseridentitydetails;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain.ProvenUserIdentityDetails;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.ConfigServiceHelper;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressMultipleAddresses;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressMultipleAddressesNoValidFrom;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianKbvM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportM1aFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportMissingBirthDate;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportMissingName;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IPV_SESSION_ID_HEADER;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IP_ADDRESS_HEADER;

@ExtendWith(MockitoExtension.class)
class BuildProvenUserIdentityDetailsHandlerTest {
    private static final String SESSION_ID = "the-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock private Context context;
    @Mock Config mockConfig;
    @Mock private ConfigService mockConfigService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @Mock private MockedStatic<VcHelper> mockVcHelper;

    @Spy
    private UserIdentityService userIdentityService = new UserIdentityService(mockConfigService);

    @InjectMocks private BuildProvenUserIdentityDetailsHandler handler;

    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeEach
    void setUp() {
        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .state("test-state")
                        .responseType("code")
                        .redirectUri("https://example.com/redirect")
                        .govukSigninJourneyId("test-journey-id")
                        .userId(TEST_USER_ID)
                        .build();

        Mockito.lenient()
                .when(mockIpvSessionItem.getClientOAuthSessionId())
                .thenReturn(TEST_CLIENT_OAUTH_SESSION_ID);
        Mockito.lenient().when(mockIpvSessionItem.getVot()).thenReturn(Vot.P2);

        ConfigServiceHelper.stubDefaultComponentIdConfig(mockConfigService, mockConfig);
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetails() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockSessionCredentialsService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                vcWebPassportSuccessful(),
                                vcAddressM1a(),
                                vcExperianFraudM1a(),
                                vcExperianKbvM1a()));
        when(VcHelper.isSuccessfulVc(any())).thenReturn(true, true, true, true, true);

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("1965-07-08", provenUserIdentityDetails.getDateOfBirth());
        assertEquals("BA2 5AA", provenUserIdentityDetails.getAddresses().get(0).getPostalCode());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockSessionCredentialsService).getCredentials(SESSION_ID, TEST_USER_ID);
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetailsWithNameAndDoBOnDifferentVcs()
            throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(VcHelper.isSuccessfulVc(any())).thenReturn(true, true, true, true, true);
        when(mockSessionCredentialsService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                vcWebPassportMissingName(),
                                vcWebPassportMissingBirthDate(),
                                vcAddressM1a(),
                                vcExperianFraudM1a(),
                                vcExperianKbvM1a()));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("1965-07-08", provenUserIdentityDetails.getDateOfBirth());
        assertEquals("BA2 5AA", provenUserIdentityDetails.getAddresses().get(0).getPostalCode());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetailsWithCorrectlyOrderedAddressHistory()
            throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(VcHelper.isSuccessfulVc(any())).thenReturn(true, true, true, true);
        when(mockSessionCredentialsService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                vcWebPassportSuccessful(),
                                vcAddressMultipleAddresses(),
                                vcExperianFraudM1a(),
                                vcExperianKbvM1a()));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        var addresses = provenUserIdentityDetails.getAddresses();
        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("KENNETH", provenUserIdentityDetails.getNameParts().get(0).getValue());
        assertEquals("1965-07-08", provenUserIdentityDetails.getDateOfBirth());
        assertEquals(3, addresses.size());
        assertEquals("CA14 5PH", addresses.get(0).getPostalCode());
        assertEquals("TE5 7ER", addresses.get(1).getPostalCode());
        assertEquals("BA2 5AA", addresses.get(2).getPostalCode());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void
            shouldReceive200ResponseCodeProvenUserIdentityDetailsWith1stAddressIfCurrentAddressCantBeFound()
                    throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(VcHelper.isSuccessfulVc(any())).thenReturn(true).thenReturn(true).thenReturn(true);
        when(mockSessionCredentialsService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                vcWebPassportSuccessful(),
                                vcAddressMultipleAddressesNoValidFrom(),
                                vcExperianFraudM1a(),
                                vcExperianKbvM1a()));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("KENNETH", provenUserIdentityDetails.getNameParts().get(0).getValue());
        assertEquals("1965-07-08", provenUserIdentityDetails.getDateOfBirth());
        assertEquals("CA14 5PH", provenUserIdentityDetails.getAddresses().get(0).getPostalCode());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive400ResponseCodeWhenEvidenceVcIsMissing() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockSessionCredentialsService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(List.of(vcAddressM1a(), vcExperianFraudM1a(), vcExperianKbvM1a()));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        var output = handler.handleRequest(input, context);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, output.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS,
                toResponseClass(output, ErrorResponse.class));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive400ResponseCodeWhenAddressVcIsMissing() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockSessionCredentialsService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                vcWebPassportSuccessful(),
                                vcExperianFraudM1a(),
                                vcExperianKbvM1a()));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        var output = handler.handleRequest(input, context);

        assertEquals(500, output.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS,
                toResponseClass(output, ErrorResponse.class));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive500ResponseCodeWhenEvidenceVcIsNotSuccessful() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockSessionCredentialsService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                vcWebPassportM1aFailed(),
                                vcAddressM1a(),
                                vcExperianFraudM1a(),
                                vcExperianKbvM1a()));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        var output = handler.handleRequest(input, context);

        assertEquals(500, output.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS,
                toResponseClass(output, ErrorResponse.class));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive500ResponseCodeWhenMissingNameInVcs() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockSessionCredentialsService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                vcWebPassportMissingName(),
                                vcAddressM1a(),
                                vcExperianFraudM1a(),
                                vcExperianKbvM1a()));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        var output = handler.handleRequest(input, context);

        assertEquals(500, output.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS,
                toResponseClass(output, ErrorResponse.class));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive500ResponseCodeWhenMissingDoBInVcs() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockSessionCredentialsService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                vcWebPassportMissingBirthDate(),
                                vcAddressM1a(),
                                vcExperianFraudM1a(),
                                vcExperianKbvM1a()));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        var output = handler.handleRequest(input, context);

        assertEquals(500, output.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS,
                toResponseClass(output, ErrorResponse.class));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    @MockitoSettings(strictness = LENIENT)
    void shouldReceive400ResponseCodeIfMissingSessionId() throws Exception {
        var input =
                new APIGatewayProxyRequestEvent().withHeaders(Map.of(IP_ADDRESS_HEADER, "1.2.3.4"));

        var output = handler.handleRequest(input, context);

        assertEquals(400, output.getStatusCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID, toResponseClass(output, ErrorResponse.class));
    }

    @Test
    @MockitoSettings(strictness = LENIENT)
    void shouldReturnErrorResponseWhenErrorGettingVcFromSessionCredentialsService()
            throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockSessionCredentialsService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenThrow(new VerifiableCredentialException(418, FAILED_TO_GET_CREDENTIAL));

        var input = createRequestEvent();

        var output = handler.handleRequest(input, context);

        assertEquals(418, output.getStatusCode());
        assertEquals(FAILED_TO_GET_CREDENTIAL, toResponseClass(output, ErrorResponse.class));
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetailsForGPGProfile() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(VcHelper.isSuccessfulVc(any())).thenReturn(true, true, true, true, true);
        when(mockSessionCredentialsService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                vcWebPassportSuccessful(),
                                vcAddressM1a(),
                                vcExperianFraudM1a(),
                                vcExperianKbvM1a()));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("KENNETH", provenUserIdentityDetails.getNameParts().get(0).getValue());
        assertEquals("1965-07-08", provenUserIdentityDetails.getDateOfBirth());
        assertEquals("BA2 5AA", provenUserIdentityDetails.getAddresses().get(0).getPostalCode());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    private APIGatewayProxyRequestEvent createRequestEvent() {
        return new APIGatewayProxyRequestEvent()
                .withHeaders(
                        Map.of(IPV_SESSION_ID_HEADER, SESSION_ID, IP_ADDRESS_HEADER, "10.10.10.1"));
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(anyString()))
                .thenThrow(new RuntimeException("Test error"));
        var input = createRequestEvent();

        var logCollector =
                LogCollector.getLogCollectorFor(BuildProvenUserIdentityDetailsHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> handler.handleRequest(input, context),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private <T> T toResponseClass(
            APIGatewayProxyResponseEvent handlerOutput, Class<T> responseClass)
            throws JsonProcessingException {
        return OBJECT_MAPPER.readValue(handlerOutput.getBody(), responseClass);
    }
}
