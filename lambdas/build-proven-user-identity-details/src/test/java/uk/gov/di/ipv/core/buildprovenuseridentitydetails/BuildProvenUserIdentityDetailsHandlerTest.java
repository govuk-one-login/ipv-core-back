package uk.gov.di.ipv.core.buildprovenuseridentitydetails;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain.ProvenUserIdentityDetails;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FAILED_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_MULTI_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_MULTI_ADDRESS_VC_WITHOUT_VALID_FROM_FIELD;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_VERIFICATION_VC;

@ExtendWith(MockitoExtension.class)
class BuildProvenUserIdentityDetailsHandlerTest {

    private static final String SESSION_ID = "the-session-id";
    private static final String TEST_USER_ID = "test-user-id";

    @Mock private Context context;
    @Mock private ConfigService mockConfigService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private IpvSessionItem mockIpvSessionItem;

    private BuildProvenUserIdentityDetailsHandler underTest;
    private ClientSessionDetailsDto clientSessionDetailsDto;
    private ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        underTest =
                new BuildProvenUserIdentityDetailsHandler(
                        mockIpvSessionService, mockUserIdentityService, mockConfigService);

        clientSessionDetailsDto = new ClientSessionDetailsDto();
        clientSessionDetailsDto.setUserId(TEST_USER_ID);
        clientSessionDetailsDto.setGovukSigninJourneyId("test-journey-id");
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetails() throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockConfigService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn("address");
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(
                                        "user-id-1", "ukPassport", M1A_PASSPORT_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "address", M1A_ADDRESS_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "fraud", M1A_FRAUD_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "kbv", M1A_VERIFICATION_VC, Instant.now())));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("ukPassport"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-p.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("address"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-a.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", "12345"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        ProvenUserIdentityDetails provenUserIdentityDetails =
                objectMapper.readValue(response.getBody(), ProvenUserIdentityDetails.class);

        assertEquals(200, response.getStatusCode());
        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("1959-08-23", provenUserIdentityDetails.getDateOfBirth());
        assertEquals("BA2 5AA", provenUserIdentityDetails.getAddresses().get(0).getPostalCode());
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetailsWithCorrectlyOrderedAddressHistory()
            throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockConfigService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn("address");
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(
                                        "user-id-1", "ukPassport", M1A_PASSPORT_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1",
                                        "address",
                                        M1A_MULTI_ADDRESS_VC,
                                        Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "fraud", M1A_FRAUD_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "kbv", M1A_VERIFICATION_VC, Instant.now())));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("ukPassport"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-p.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("address"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-a.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", "12345"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        ProvenUserIdentityDetails provenUserIdentityDetails =
                objectMapper.readValue(response.getBody(), ProvenUserIdentityDetails.class);

        List<Address> addresses = provenUserIdentityDetails.getAddresses();
        assertEquals(200, response.getStatusCode());
        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("1959-08-23", provenUserIdentityDetails.getDateOfBirth());
        assertEquals(3, addresses.size());
        assertEquals("CA14 5PH", addresses.get(0).getPostalCode());
        assertEquals("TE5 7ER", addresses.get(1).getPostalCode());
        assertEquals("BA2 5AA", addresses.get(2).getPostalCode());
    }

    @Test
    void
            shouldReceive200ResponseCodeProvenUserIdentityDetailsWith1stAddressIfCurrentAddressCantBeFound()
                    throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockConfigService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn("address");
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(
                                        "user-id-1", "ukPassport", M1A_PASSPORT_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1",
                                        "address",
                                        M1A_MULTI_ADDRESS_VC_WITHOUT_VALID_FROM_FIELD,
                                        Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "fraud", M1A_FRAUD_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "kbv", M1A_VERIFICATION_VC, Instant.now())));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("ukPassport"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-p.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("address"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-a.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", "12345"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        ProvenUserIdentityDetails provenUserIdentityDetails =
                objectMapper.readValue(response.getBody(), ProvenUserIdentityDetails.class);

        assertEquals(200, response.getStatusCode());
        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("1959-08-23", provenUserIdentityDetails.getDateOfBirth());
        assertEquals("BA2 5AA", provenUserIdentityDetails.getAddresses().get(0).getPostalCode());
    }

    @Test
    void shouldReceive400ResponseCodeWhenEvidenceVcIsMissing() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockConfigService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn("address");
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("address"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-a.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(
                                        "user-id-1", "address", M1A_ADDRESS_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "fraud", M1A_FRAUD_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "kbv", M1A_VERIFICATION_VC, Instant.now())));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", "12345"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> errorResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals(
                String.valueOf(
                        ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS.getCode()),
                errorResponse.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS.getMessage(),
                errorResponse.get("message"));
    }

    @Test
    void shouldReceive400ResponseCodeWhenAddressVcIsMissing() throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockConfigService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn("address");
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(
                                        "user-id-1", "ukPassport", M1A_PASSPORT_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "fraud", M1A_FRAUD_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "kbv", M1A_VERIFICATION_VC, Instant.now())));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("ukPassport"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-p.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("address"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-a.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("fraud"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-f.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("kbv"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-k.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", "12345"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> errorResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals(
                String.valueOf(
                        ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS.getCode()),
                errorResponse.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS.getMessage(),
                errorResponse.get("message"));
    }

    @Test
    void shouldReceive400ResponseCodeWhenEvidenceVcIsNotSuccessful() throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockConfigService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn("address");
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(
                                        "user-id-1",
                                        "ukPassport",
                                        M1A_FAILED_PASSPORT_VC,
                                        Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "address", M1A_ADDRESS_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "fraud", M1A_FRAUD_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "kbv", M1A_VERIFICATION_VC, Instant.now())));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("ukPassport"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-p.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("address"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-a.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("fraud"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-f.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("kbv"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                true,
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "https://review-k.integration.account.gov.uk",
                                URI.create("https://example.com/callback"),
                                true,
                                "main"));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", "12345"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> errorResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals(
                String.valueOf(
                        ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS.getCode()),
                errorResponse.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS.getMessage(),
                errorResponse.get("message"));
    }

    @Test
    void shouldReceive400ResponseCodeIfMissingSessionId() throws Exception {
        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setHeaders(Map.of("ip-address", "12345"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> errorResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(400, response.getStatusCode());
        assertEquals(
                String.valueOf(ErrorResponse.MISSING_IPV_SESSION_ID.getCode()),
                errorResponse.get("error"));
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(),
                errorResponse.get("error_description"));
    }

    @Test
    void shouldReceive500ResponseCodeWhenFailedToParseVc() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(clientSessionDetailsDto);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(
                                        "user-id-1",
                                        "ukPassport",
                                        "invalid-credential",
                                        Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "address", M1A_ADDRESS_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "fraud", M1A_FRAUD_VC, Instant.now()),
                                createVcStoreItem(
                                        "user-id-1", "kbv", M1A_VERIFICATION_VC, Instant.now())));

        APIGatewayProxyRequestEvent input = createRequestEvent();

        input.setHeaders(Map.of("ipv-session-id", SESSION_ID, "ip-address", "12345"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        Map<String, String> errorResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals(
                String.valueOf(ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode()),
                errorResponse.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(),
                errorResponse.get("message"));
    }

    private APIGatewayProxyRequestEvent createRequestEvent() {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", "aSessionId", "ip-address", "1234"));
        return input;
    }

    private VcStoreItem createVcStoreItem(
            String userId, String credentialIssuer, String credential, Instant dateCreated) {
        VcStoreItem vcStoreItem = new VcStoreItem();
        vcStoreItem.setUserId(userId);
        vcStoreItem.setCredentialIssuer(credentialIssuer);
        vcStoreItem.setCredential(credential);
        vcStoreItem.setDateCreated(dateCreated);
        vcStoreItem.setExpirationTime(dateCreated.plusSeconds(1000L));
        return vcStoreItem;
    }
}
