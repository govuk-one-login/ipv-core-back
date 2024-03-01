package uk.gov.di.ipv.core.buildprovenuseridentitydetails;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain.ProvenUserIdentityDetails;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.NoVcStatusForIssuerException;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.EXPERIAN_FRAUD_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.EXPERIAN_KBV_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.HMRC_MIGRATION_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressMultipleAddresses;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressMultipleAddressesNoValidFrom;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigration;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportM1aFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportMissingBirthDate;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportMissingName;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportNonDcmawSuccessful;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcVerificationM1a;

@ExtendWith(MockitoExtension.class)
class BuildProvenUserIdentityDetailsHandlerTest {
    private static final String SESSION_ID = "the-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final OauthCriConfig ISSUER_CONFIG_ADDRESS =
            createCredentialIssuerConfig("https://review-a.integration.account.gov.uk");
    private static final OauthCriConfig ISSUER_CONFIG_CLAIMED_IDENTITY =
            createCredentialIssuerConfig("https://review-c.integration.account.gov.uk");
    @Mock private Context context;
    @Mock private ConfigService mockConfigService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private IpvSessionItem mockIpvSessionItem;

    private BuildProvenUserIdentityDetailsHandler handler;
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

        handler =
                new BuildProvenUserIdentityDetailsHandler(
                        mockIpvSessionService,
                        mockUserIdentityService,
                        mockConfigService,
                        mockClientOAuthSessionDetailsService,
                        mockVerifiableCredentialService);

        when(mockIpvSessionItem.getClientOAuthSessionId()).thenReturn(TEST_CLIENT_OAUTH_SESSION_ID);
        when(mockIpvSessionItem.getVot()).thenReturn(Vot.P2);
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetails() throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockUserIdentityService.findIdentityClaim(any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, PASSPORT_CRI, vcPassportNonDcmawSuccessful()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, ADDRESS_CRI, M1A_ADDRESS_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_KBV_CRI, vcVerificationM1a())));

        when(mockConfigService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY.getComponentId());
        when(mockConfigService.getComponentId(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS.getComponentId());

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("1965-07-08", provenUserIdentityDetails.getDateOfBirth());
        assertEquals("BA2 5AA", provenUserIdentityDetails.getAddresses().get(0).getPostalCode());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetailsWithNameAndDoBOnDifferentVcs()
            throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockUserIdentityService.findIdentityClaim(any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, PASSPORT_CRI, vcPassportMissingName()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, PASSPORT_CRI, vcPassportMissingBirthDate()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, ADDRESS_CRI, M1A_ADDRESS_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_KBV_CRI, vcVerificationM1a())));

        when(mockConfigService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY.getComponentId());
        when(mockConfigService.getComponentId(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS.getComponentId());

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();

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
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockUserIdentityService.findIdentityClaim(any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, PASSPORT_CRI, vcPassportNonDcmawSuccessful()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, ADDRESS_CRI, vcAddressMultipleAddresses()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_KBV_CRI, vcVerificationM1a())));

        when(mockConfigService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY.getComponentId());
        when(mockConfigService.getComponentId(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS.getComponentId());

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        List<Address> addresses = provenUserIdentityDetails.getAddresses();
        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
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
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockUserIdentityService.findIdentityClaim(any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, PASSPORT_CRI, vcPassportNonDcmawSuccessful()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID,
                                        ADDRESS_CRI,
                                        vcAddressMultipleAddressesNoValidFrom()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_KBV_CRI, vcVerificationM1a())));

        when(mockConfigService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY.getComponentId());
        when(mockConfigService.getComponentId(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS.getComponentId());
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("1965-07-08", provenUserIdentityDetails.getDateOfBirth());
        assertEquals("CA14 5PH", provenUserIdentityDetails.getAddresses().get(0).getPostalCode());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive400ResponseCodeWhenEvidenceVcIsMissing() throws Exception {
        when(mockUserIdentityService.findIdentityClaim(any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockConfigService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY.getComponentId());
        when(mockConfigService.getComponentId(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS.getComponentId());

        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, ADDRESS_CRI, M1A_ADDRESS_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_KBV_CRI, vcVerificationM1a())));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();

        JourneyErrorResponse errorResponse =
                toResponseClass(handler.handleRequest(input, context), JourneyErrorResponse.class);

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
        when(mockUserIdentityService.findIdentityClaim(any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, PASSPORT_CRI, vcPassportNonDcmawSuccessful()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_KBV_CRI, vcVerificationM1a())));

        when(mockConfigService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY.getComponentId());
        when(mockConfigService.getComponentId(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS.getComponentId());
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();
        JourneyErrorResponse errorResponse =
                toResponseClass(handler.handleRequest(input, context), JourneyErrorResponse.class);

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
    void shouldReceive500ResponseCodeWhenEvidenceVcIsNotSuccessful() throws Exception {
        when(mockUserIdentityService.findIdentityClaim(any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, PASSPORT_CRI, vcPassportM1aFailed()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, ADDRESS_CRI, M1A_ADDRESS_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_KBV_CRI, vcVerificationM1a())));

        when(mockConfigService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY.getComponentId());
        when(mockConfigService.getComponentId(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS.getComponentId());
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();
        JourneyErrorResponse errorResponse =
                toResponseClass(handler.handleRequest(input, context), JourneyErrorResponse.class);

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
    void shouldReceive500ResponseCodeWhenMissingNameInVcs() throws Exception {
        when(mockUserIdentityService.findIdentityClaim(any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, PASSPORT_CRI, vcPassportMissingName()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, ADDRESS_CRI, M1A_ADDRESS_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_KBV_CRI, vcVerificationM1a())));

        when(mockConfigService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY.getComponentId());
        when(mockConfigService.getComponentId(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS.getComponentId());
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();
        JourneyErrorResponse errorResponse =
                toResponseClass(handler.handleRequest(input, context), JourneyErrorResponse.class);

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
    void shouldReceive500ResponseCodeWhenMissingDoBInVcs() throws Exception {
        when(mockUserIdentityService.findIdentityClaim(any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, PASSPORT_CRI, vcPassportMissingBirthDate()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, ADDRESS_CRI, M1A_ADDRESS_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_KBV_CRI, vcVerificationM1a())));

        when(mockConfigService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY.getComponentId());
        when(mockConfigService.getComponentId(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS.getComponentId());
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();
        JourneyErrorResponse errorResponse =
                toResponseClass(handler.handleRequest(input, context), JourneyErrorResponse.class);

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
    @MockitoSettings(strictness = Strictness.LENIENT)
    void shouldReceive400ResponseCodeIfMissingSessionId() {
        JourneyRequest input =
                JourneyRequest.builder().ipAddress("ip-address").featureSet("12345").build();
        JourneyErrorResponse errorResponse =
                toResponseClass(handler.handleRequest(input, context), JourneyErrorResponse.class);

        assertEquals(400, errorResponse.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), errorResponse.getCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), errorResponse.getMessage());
    }

    @Test
    void shouldReceive500ResponseCodeWhenFailedToParseVc() {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, PASSPORT_CRI, "invalid-credential"),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, ADDRESS_CRI, M1A_ADDRESS_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_KBV_CRI, vcVerificationM1a())));

        JourneyRequest input = createRequestEvent();
        JourneyErrorResponse errorResponse =
                toResponseClass(handler.handleRequest(input, context), JourneyErrorResponse.class);

        assertEquals(500, errorResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode(),
                errorResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(),
                errorResponse.getMessage());
    }

    @Test
    void shouldReturn500IfNoVcStatusForIssuer() throws Exception {
        when(mockUserIdentityService.findIdentityClaim(any())).thenCallRealMethod();
        when(mockUserIdentityService.isVcSuccessful(any(), any()))
                .thenThrow(new NoVcStatusForIssuerException("Bad"));
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, PASSPORT_CRI, vcPassportNonDcmawSuccessful()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, ADDRESS_CRI, M1A_ADDRESS_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_KBV_CRI, vcVerificationM1a())));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();
        JourneyErrorResponse errorResponse =
                toResponseClass(handler.handleRequest(input, context), JourneyErrorResponse.class);

        assertEquals(500, errorResponse.getStatusCode());
        assertEquals(
                ErrorResponse.NO_VC_STATUS_FOR_CREDENTIAL_ISSUER.getCode(),
                errorResponse.getCode());
        assertEquals(
                ErrorResponse.NO_VC_STATUS_FOR_CREDENTIAL_ISSUER.getMessage(),
                errorResponse.getMessage());
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetailsForGPGProfile() throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenCallRealMethod();
        when(mockUserIdentityService.findIdentityClaim(any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, PASSPORT_CRI, vcPassportNonDcmawSuccessful()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, ADDRESS_CRI, M1A_ADDRESS_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_KBV_CRI, vcVerificationM1a()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, HMRC_MIGRATION_CRI, vcHmrcMigration())));

        when(mockConfigService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY.getComponentId());
        when(mockConfigService.getComponentId(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS.getComponentId());

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("1965-07-08", provenUserIdentityDetails.getDateOfBirth());
        assertEquals("BA2 5AA", provenUserIdentityDetails.getAddresses().get(0).getPostalCode());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetailsForOperationalProfile()
            throws Exception {
        when(mockUserIdentityService.findIdentityClaim(any())).thenCallRealMethod();
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getVot()).thenReturn(Vot.PCL250);
        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, PASSPORT_CRI, vcPassportNonDcmawSuccessful()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, ADDRESS_CRI, M1A_ADDRESS_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, EXPERIAN_KBV_CRI, vcVerificationM1a()),
                                TestFixtures.createVcStoreItem(
                                        TEST_USER_ID, HMRC_MIGRATION_CRI, vcHmrcMigration())));

        when(mockConfigService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(ISSUER_CONFIG_CLAIMED_IDENTITY.getComponentId());
        when(mockConfigService.getComponentId(ADDRESS_CRI))
                .thenReturn(ISSUER_CONFIG_ADDRESS.getComponentId());

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals("1965-07-08", provenUserIdentityDetails.getDateOfBirth());
        assertNull(provenUserIdentityDetails.getAddresses());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    private JourneyRequest createRequestEvent() {
        return JourneyRequest.builder().ipvSessionId(SESSION_ID).ipAddress("10.10.10.1").build();
    }

    private static OauthCriConfig createCredentialIssuerConfig(String componentId) {
        return OauthCriConfig.builder()
                .tokenUrl(URI.create("https://example.com/token"))
                .credentialUrl(URI.create("https://example.com/credential"))
                .authorizeUrl(URI.create("https://example.com/authorize"))
                .clientId("ipv-core")
                .signingKey("test-jwk")
                .encryptionKey("test-jwk")
                .componentId(componentId)
                .clientCallbackUrl(URI.create("https://example.com/callback"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }

    private <T> T toResponseClass(Map<String, Object> handlerOutput, Class<T> responseClass) {
        return objectMapper.convertValue(handlerOutput, responseClass);
    }
}
