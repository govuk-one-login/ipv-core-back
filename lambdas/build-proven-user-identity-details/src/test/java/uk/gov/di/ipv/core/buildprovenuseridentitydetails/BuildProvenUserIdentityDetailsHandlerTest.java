package uk.gov.di.ipv.core.buildprovenuseridentitydetails;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain.ProvenUserIdentityDetails;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.NoVcStatusForIssuerException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.SESSION_CREDENTIALS_TABLE_READS;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressMultipleAddresses;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressMultipleAddressesNoValidFrom;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigration;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportM1aFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportMissingBirthDate;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportMissingName;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcVerificationM1a;
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
    @Mock private ConfigService mockConfigService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @Mock private MockedStatic<VcHelper> mockVcHelper;
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

        when(mockIpvSessionItem.getClientOAuthSessionId()).thenReturn(TEST_CLIENT_OAUTH_SESSION_ID);
        when(mockIpvSessionItem.getVot()).thenReturn(Vot.P2);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldReceive200ResponseCodeProvenUserIdentityDetails(boolean sessionCredentialsReads)
            throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenReturn(true);
        when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(createIdentityClaim());
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockConfigService.enabled(SESSION_CREDENTIALS_TABLE_READS))
                .thenReturn(sessionCredentialsReads);
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        M1A_ADDRESS_VC,
                        M1A_EXPERIAN_FRAUD_VC,
                        vcVerificationM1a());
        if (sessionCredentialsReads) {
            when(mockSessionCredentialsService.getCredentials(SESSION_ID, TEST_USER_ID))
                    .thenReturn(vcs);
        } else {
            when(VcHelper.filterVCBasedOnProfileType(any(), any())).thenReturn(vcs);
        }
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
        if (sessionCredentialsReads) {
            verify(mockSessionCredentialsService).getCredentials(SESSION_ID, TEST_USER_ID);
        } else {
            mockVcHelper.verify(() -> VcHelper.filterVCBasedOnProfileType(any(), any()));
        }
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetailsWithNameAndDoBOnDifferentVcs()
            throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenReturn(true);
        when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(createIdentityClaim());
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(VcHelper.isSuccessfulVc(any())).thenReturn(true, true, true, true, true);
        when(VcHelper.filterVCBasedOnProfileType(any(), any()))
                .thenReturn(
                        List.of(
                                vcPassportMissingName(),
                                vcPassportMissingBirthDate(),
                                M1A_ADDRESS_VC,
                                M1A_EXPERIAN_FRAUD_VC,
                                vcVerificationM1a()));

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
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenReturn(true);
        when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(createIdentityClaim());
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(VcHelper.isSuccessfulVc(any())).thenReturn(true, true, true, true);
        when(VcHelper.filterVCBasedOnProfileType(any(), any()))
                .thenReturn(
                        List.of(
                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                                vcAddressMultipleAddresses(),
                                M1A_EXPERIAN_FRAUD_VC,
                                vcVerificationM1a()));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        List<Address> addresses = provenUserIdentityDetails.getAddresses();
        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals(
                "KENNETH DECERQUEIRA",
                provenUserIdentityDetails.getFormattedName().get("dummyType"));
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
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenReturn(true);
        when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(createIdentityClaim());
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(VcHelper.isSuccessfulVc(any())).thenReturn(true).thenReturn(true).thenReturn(true);
        when(VcHelper.filterVCBasedOnProfileType(any(), any()))
                .thenReturn(
                        List.of(
                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                                vcAddressMultipleAddressesNoValidFrom(),
                                M1A_EXPERIAN_FRAUD_VC,
                                vcVerificationM1a()));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals(
                "KENNETH DECERQUEIRA",
                provenUserIdentityDetails.getFormattedName().get("dummyType"));
        assertEquals("1965-07-08", provenUserIdentityDetails.getDateOfBirth());
        assertEquals("CA14 5PH", provenUserIdentityDetails.getAddresses().get(0).getPostalCode());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive400ResponseCodeWhenEvidenceVcIsMissing() throws Exception {
        when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(createIdentityClaim());
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);

        mockVcHelper
                .when(() -> VcHelper.filterVCBasedOnProfileType(any(), any()))
                .thenReturn(List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC, vcVerificationM1a()));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        var output = handler.handleRequest(input, context);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PROVEN_USER_IDENTITY_DETAILS,
                toResponseClass(output, ErrorResponse.class));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive400ResponseCodeWhenAddressVcIsMissing() throws Exception {
        when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(createIdentityClaim());
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                                M1A_EXPERIAN_FRAUD_VC,
                                vcVerificationM1a()));

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
        when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(createIdentityClaim());
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                vcPassportM1aFailed(),
                                M1A_ADDRESS_VC,
                                M1A_EXPERIAN_FRAUD_VC,
                                vcVerificationM1a()));

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
        when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(createIdentityClaim());
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                vcPassportMissingName(),
                                M1A_ADDRESS_VC,
                                M1A_EXPERIAN_FRAUD_VC,
                                vcVerificationM1a()));

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
        when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(createIdentityClaim());
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                vcPassportMissingBirthDate(),
                                M1A_ADDRESS_VC,
                                M1A_EXPERIAN_FRAUD_VC,
                                vcVerificationM1a()));

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
    @MockitoSettings(strictness = Strictness.LENIENT)
    void shouldReceive400ResponseCodeIfMissingSessionId() throws Exception {
        var input =
                new APIGatewayProxyRequestEvent().withHeaders(Map.of(IP_ADDRESS_HEADER, "1.2.3.4"));

        var output = handler.handleRequest(input, context);

        assertEquals(400, output.getStatusCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID, toResponseClass(output, ErrorResponse.class));
    }

    @Test
    void shouldReceive500ResponseCodeWhenFailedToParseVc() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID))
                .thenThrow(new CredentialParseException("Invalid credentials!"));

        var input = createRequestEvent();

        var output = handler.handleRequest(input, context);

        assertEquals(500, output.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS,
                toResponseClass(output, ErrorResponse.class));
    }

    @Test
    void shouldReturnErrorResponseWhenErrorGettingVcFromSessionCredentialsService()
            throws Exception {
        when(mockConfigService.enabled(SESSION_CREDENTIALS_TABLE_READS)).thenReturn(true);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockSessionCredentialsService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenThrow(
                        new VerifiableCredentialException(
                                418, ErrorResponse.FAILED_TO_GET_CREDENTIAL));

        var input = createRequestEvent();

        var output = handler.handleRequest(input, context);

        assertEquals(418, output.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GET_CREDENTIAL,
                toResponseClass(output, ErrorResponse.class));
    }

    @Test
    void shouldReturn500IfNoVcStatusForIssuer() throws Exception {
        when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(createIdentityClaim());
        when(mockUserIdentityService.isVcSuccessful(any(), any()))
                .thenThrow(new NoVcStatusForIssuerException("Bad"));
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(VcHelper.isSuccessfulVc(any())).thenReturn(true, true, true, true);
        when(VcHelper.filterVCBasedOnProfileType(any(), any()))
                .thenReturn(
                        List.of(
                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                                M1A_ADDRESS_VC,
                                M1A_EXPERIAN_FRAUD_VC,
                                vcVerificationM1a()));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        var output = handler.handleRequest(input, context);

        assertEquals(500, output.getStatusCode());
        assertEquals(
                ErrorResponse.NO_VC_STATUS_FOR_CREDENTIAL_ISSUER,
                toResponseClass(output, ErrorResponse.class));
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetailsForGPGProfile() throws Exception {
        when(mockUserIdentityService.isVcSuccessful(any(), any())).thenReturn(true);
        when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(createIdentityClaim());
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(VcHelper.isSuccessfulVc(any())).thenReturn(true, true, true, true, true);
        when(VcHelper.filterVCBasedOnProfileType(any(), any()))
                .thenReturn(
                        List.of(
                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                                M1A_ADDRESS_VC,
                                M1A_EXPERIAN_FRAUD_VC,
                                vcVerificationM1a(),
                                vcHmrcMigration()));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals(
                "KENNETH DECERQUEIRA",
                provenUserIdentityDetails.getFormattedName().get("dummyType"));
        assertEquals("1965-07-08", provenUserIdentityDetails.getDateOfBirth());
        assertEquals("BA2 5AA", provenUserIdentityDetails.getAddresses().get(0).getPostalCode());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive200ResponseCodeProvenUserIdentityDetailsForOperationalProfile()
            throws Exception {
        when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(createIdentityClaim());
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getVot()).thenReturn(Vot.PCL250);
        when(VcHelper.isSuccessfulVc(any())).thenReturn(true, true, true, true, true);
        when(VcHelper.filterVCBasedOnProfileType(any(), any()))
                .thenReturn(
                        List.of(
                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                                M1A_ADDRESS_VC,
                                M1A_EXPERIAN_FRAUD_VC,
                                vcVerificationM1a(),
                                vcHmrcMigration()));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var input = createRequestEvent();

        ProvenUserIdentityDetails provenUserIdentityDetails =
                toResponseClass(
                        handler.handleRequest(input, context), ProvenUserIdentityDetails.class);

        assertEquals("KENNETH DECERQUEIRA", provenUserIdentityDetails.getName());
        assertEquals(
                "KENNETH DECERQUEIRA",
                provenUserIdentityDetails.getFormattedName().get("dummyType"));
        assertEquals("1965-07-08", provenUserIdentityDetails.getDateOfBirth());
        assertNull(provenUserIdentityDetails.getAddresses());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    private APIGatewayProxyRequestEvent createRequestEvent() {
        return new APIGatewayProxyRequestEvent()
                .withHeaders(
                        Map.of(IPV_SESSION_ID_HEADER, SESSION_ID, IP_ADDRESS_HEADER, "10.10.10.1"));
    }

    private Optional<IdentityClaim> createIdentityClaim() {
        var names =
                Collections.singletonList(
                        new Name(
                                Collections.singletonList(
                                        new NameParts("KENNETH DECERQUEIRA", "dummyType"))));
        var birthDates = Collections.singletonList(new BirthDate("1965-07-08"));

        return Optional.of(new IdentityClaim(names, birthDates));
    }

    private <T> T toResponseClass(
            APIGatewayProxyResponseEvent handlerOutput, Class<T> responseClass)
            throws JsonProcessingException {
        return OBJECT_MAPPER.readValue(handlerOutput.getBody(), responseClass);
    }
}
