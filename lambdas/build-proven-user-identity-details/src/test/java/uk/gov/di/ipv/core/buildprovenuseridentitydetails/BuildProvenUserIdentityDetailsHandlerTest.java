package uk.gov.di.ipv.core.buildprovenuseridentitydetails;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain.ProvenUserIdentityDetails;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.BaseResponse;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.FRAUD_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.KBV_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;
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
    private static final String TEST_CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.generate();
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final CredentialIssuerConfig ISSUER_CONFIG_ADDRESS =
            createCredentialIssuerConfig("https://review-a.integration.account.gov.uk");
    private static final CredentialIssuerConfig ISSUER_CONFIG_CLAIMED_IDENTITY =
            createCredentialIssuerConfig("https://review-c.integration.account.gov.uk");
    private static final CredentialIssuerConfig ISSUER_CONFIG_FRAUD =
            createCredentialIssuerConfig("https://review-f.integration.account.gov.uk");
    private static final CredentialIssuerConfig ISSUER_CONFIG_KBV =
            createCredentialIssuerConfig("https://review-k.integration.account.gov.uk");
    private static final CredentialIssuerConfig ISSUER_CONFIG_UK_PASSPORT =
            createCredentialIssuerConfig("https://review-p.integration.account.gov.uk");

    @Mock private Context context;
    @Mock private ConfigService mockConfigService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private IpvSessionItem mockIpvSessionItem;

    private BuildProvenUserIdentityDetailsHandler underTest;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeEach
    void setUp() {
        underTest =
                new BuildProvenUserIdentityDetailsHandler(
                        mockIpvSessionService,
                        mockUserIdentityService,
                        mockConfigService,
                        mockClientOAuthSessionDetailsService);

        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .state("test-state")
                        .responseType("code")
                        .redirectUri("https://example.com/redirect")
                        .govukSigninJourneyId("test-journey-id")
                        .userId(TEST_USER_ID)
                        .build();
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetails() throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientOAuthSessionId()).thenReturn(TEST_CLIENT_OAUTH_SESSION_ID);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(PASSPORT_CRI, M1A_PASSPORT_VC),
                                createVcStoreItem(ADDRESS_CRI, M1A_ADDRESS_VC),
                                createVcStoreItem(FRAUD_CRI, M1A_FRAUD_VC),
                                createVcStoreItem(KBV_CRI, M1A_VERIFICATION_VC)));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(ISSUER_CONFIG_UK_PASSPORT);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS);

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();
        var provenUserIdentityDetails =
                makeRequest(input, context, ProvenUserIdentityDetails.class);

        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("1959-08-23", provenUserIdentityDetails.getDateOfBirth());
        assertEquals("BA2 5AA", provenUserIdentityDetails.getAddresses().get(0).getPostalCode());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetailsWithCorrectlyOrderedAddressHistory()
            throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientOAuthSessionId()).thenReturn(TEST_CLIENT_OAUTH_SESSION_ID);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(PASSPORT_CRI, M1A_PASSPORT_VC),
                                createVcStoreItem(ADDRESS_CRI, M1A_MULTI_ADDRESS_VC),
                                createVcStoreItem(FRAUD_CRI, M1A_FRAUD_VC),
                                createVcStoreItem(KBV_CRI, M1A_VERIFICATION_VC)));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(ISSUER_CONFIG_UK_PASSPORT);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS);

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();
        var provenUserIdentityDetails =
                makeRequest(input, context, ProvenUserIdentityDetails.class);

        List<Address> addresses = provenUserIdentityDetails.getAddresses();
        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("1959-08-23", provenUserIdentityDetails.getDateOfBirth());
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
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientOAuthSessionId()).thenReturn(TEST_CLIENT_OAUTH_SESSION_ID);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(PASSPORT_CRI, M1A_PASSPORT_VC),
                                createVcStoreItem(
                                        ADDRESS_CRI, M1A_MULTI_ADDRESS_VC_WITHOUT_VALID_FROM_FIELD),
                                createVcStoreItem(FRAUD_CRI, M1A_FRAUD_VC),
                                createVcStoreItem(KBV_CRI, M1A_VERIFICATION_VC)));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(ISSUER_CONFIG_UK_PASSPORT);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();
        var provenUserIdentityDetails =
                makeRequest(input, context, ProvenUserIdentityDetails.class);

        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("1959-08-23", provenUserIdentityDetails.getDateOfBirth());
        assertEquals("BA2 5AA", provenUserIdentityDetails.getAddresses().get(0).getPostalCode());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive400ResponseCodeWhenEvidenceVcIsMissing() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS);

        when(mockIpvSessionItem.getClientOAuthSessionId()).thenReturn(TEST_CLIENT_OAUTH_SESSION_ID);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(ADDRESS_CRI, M1A_ADDRESS_VC),
                                createVcStoreItem(FRAUD_CRI, M1A_FRAUD_VC),
                                createVcStoreItem(KBV_CRI, M1A_VERIFICATION_VC)));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();
        var errorResponse = makeRequest(input, context, JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, errorResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS.getCode(),
                errorResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS.getMessage(),
                errorResponse.getMessage());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive400ResponseCodeWhenAddressVcIsMissing() throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientOAuthSessionId()).thenReturn(TEST_CLIENT_OAUTH_SESSION_ID);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(PASSPORT_CRI, M1A_PASSPORT_VC),
                                createVcStoreItem(FRAUD_CRI, M1A_FRAUD_VC),
                                createVcStoreItem(KBV_CRI, M1A_VERIFICATION_VC)));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(ISSUER_CONFIG_UK_PASSPORT);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(ISSUER_CONFIG_FRAUD);

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(KBV_CRI))
                .thenReturn(ISSUER_CONFIG_KBV);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();
        var errorResponse = makeRequest(input, context, JourneyErrorResponse.class);

        assertEquals(500, errorResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS.getCode(),
                errorResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS.getMessage(),
                errorResponse.getMessage());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive400ResponseCodeWhenEvidenceVcIsNotSuccessful() throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientOAuthSessionId()).thenReturn(TEST_CLIENT_OAUTH_SESSION_ID);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(PASSPORT_CRI, M1A_FAILED_PASSPORT_VC),
                                createVcStoreItem(ADDRESS_CRI, M1A_ADDRESS_VC),
                                createVcStoreItem(FRAUD_CRI, M1A_FRAUD_VC),
                                createVcStoreItem(KBV_CRI, M1A_VERIFICATION_VC)));

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(ISSUER_CONFIG_UK_PASSPORT);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(ISSUER_CONFIG_FRAUD);

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(KBV_CRI))
                .thenReturn(ISSUER_CONFIG_KBV);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();
        var errorResponse = makeRequest(input, context, JourneyErrorResponse.class);

        assertEquals(500, errorResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS.getCode(),
                errorResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS.getMessage(),
                errorResponse.getMessage());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive400ResponseCodeIfMissingSessionId() throws Exception {
        JourneyRequest input =
                JourneyRequest.builder().ipAddress("ip-address").featureSet("12345").build();
        var errorResponse = makeRequest(input, context, JourneyErrorResponse.class);

        assertEquals(400, errorResponse.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), errorResponse.getCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), errorResponse.getMessage());
    }

    @Test
    void shouldReceive500ResponseCodeWhenFailedToParseVc() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getClientOAuthSessionId()).thenReturn(TEST_CLIENT_OAUTH_SESSION_ID);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockUserIdentityService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                createVcStoreItem(PASSPORT_CRI, "invalid-credential"),
                                createVcStoreItem(ADDRESS_CRI, M1A_ADDRESS_VC),
                                createVcStoreItem(FRAUD_CRI, M1A_FRAUD_VC),
                                createVcStoreItem(KBV_CRI, M1A_VERIFICATION_VC)));

        JourneyRequest input = createRequestEvent();
        var errorResponse = makeRequest(input, context, JourneyErrorResponse.class);

        assertEquals(500, errorResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode(),
                errorResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(),
                errorResponse.getMessage());
    }

    private JourneyRequest createRequestEvent() {
        return JourneyRequest.builder().ipvSessionId(SESSION_ID).ipAddress("10.10.10.1").build();
    }

    private VcStoreItem createVcStoreItem(String credentialIssuer, String credential) {
        Instant dateCreated = Instant.now();
        VcStoreItem vcStoreItem = new VcStoreItem();
        vcStoreItem.setUserId("user-id-1");
        vcStoreItem.setCredentialIssuer(credentialIssuer);
        vcStoreItem.setCredential(credential);
        vcStoreItem.setDateCreated(dateCreated);
        vcStoreItem.setExpirationTime(dateCreated.plusSeconds(1000L));
        return vcStoreItem;
    }

    private <T extends BaseResponse> T makeRequest(
            JourneyRequest request, Context context, Class<T> classType) throws IOException {
        try (var inputStream =
                        new ByteArrayInputStream(
                                objectMapper.writeValueAsString(request).getBytes());
                var outputStream = new ByteArrayOutputStream()) {
            underTest.handleRequest(inputStream, outputStream, context);
            return objectMapper.readValue(outputStream.toString(), classType);
        }
    }

    private static CredentialIssuerConfig createCredentialIssuerConfig(String componentId) {
        return new CredentialIssuerConfig(
                URI.create("https://example.com/token"),
                URI.create("https://example.com/credential"),
                URI.create("https://example.com/authorize"),
                "ipv-core",
                "test-jwk",
                "test-jwk",
                componentId,
                URI.create("https://example.com/callback"),
                true);
    }
}
