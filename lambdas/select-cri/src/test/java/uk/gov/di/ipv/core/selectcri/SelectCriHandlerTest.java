package uk.gov.di.ipv.core.selectcri;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ALLOWED_USER_IDS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_SHOULD_SEND_ALL_USERS;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DRIVING_LICENCE_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.FRAUD_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.KBV_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;

@ExtendWith(MockitoExtension.class)
class SelectCriHandlerTest {

    private static final String TEST_SESSION_ID = "the-session-id";
    private static final String APP_JOURNEY_USER_ID_PREFIX = "urn:uuid:app-journey-user-";
    private static final String PASSPORT_CRI_ISS = "test-passport-iss";
    private static final String DCMAW_CRI_ISS = "test-dcmaw-iss";
    private static final String ADDRESS_CRI_ISS = "test-address-iss";
    private static final String DRIVING_LICENSE_CRI_ISS = "test-driving-licence-iss";
    private static final String FRAUD_CRI_ISS = "test-fraud-iss";
    private static final String KBV_CRI_ISS = "test-kbv-iss";
    private static final String CLAIMED_IDENTITY_CRI_ISS = "test-claimed-identity-iss";
    private static final String F2F_CRI_ISS = "test-f2f-iss";
    private static final String UK_PASSPORT_JOURNEY = "/journey/ukPassport";
    private static final String MULTIPLE_DOC_CHECK_PAGE_JOURNEY =
            "/journey/multipleDocCheckPage";
    private static final String MULTIPLE_DOC_CHECK_WITH_F2F_PAGE_JOURNEY =
            "/journey/multipleDocCheckWithF2FPage";
    private static final String ADDRESS_JOURNEY = "/journey/address";
    private static final String PYI_NO_MATCH_JOURNEY = "/journey/pyi-no-match";
    private static final String FRAUD_JOURNEY = "/journey/fraud";
    private static final String KBV_JOURNEY = "/journey/kbv";
    private static final String FAIL_JOURNEY = "/journey/fail";
    private static final String DCMAW_JOURNEY = "/journey/dcmaw";
    private static final String DCMAW_SUCCESS_JOURNEY = "/journey/dcmaw-success";
    private static final String PYI_KBV_THIN_FILE_JOURNEY = "/journey/pyi-kbv-thin-file";
    private static final String F2F_JOURNEY = "/journey/f2f";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Mock private Context context;
    @Mock private ConfigService mockConfigService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionService;

    @InjectMocks private SelectCriHandler underTest;

    @BeforeEach
    void setUp() {
        underTest =
                new SelectCriHandler(
                        mockConfigService, mockIpvSessionService, mockClientOAuthSessionService);
    }

    @Test
    void shouldReturnPassportCriJourneyResponse() throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(UK_PASSPORT_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnPassportAndDrivingLicenceCriJourneyResponseWhenDrivingLicenceCriEnabled()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI));
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(false);
        when(mockConfigService.isEnabled(DRIVING_LICENCE_CRI)).thenReturn(true);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(MULTIPLE_DOC_CHECK_PAGE_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnPassportDrivingLicenceAndF2FCriJourneyResponseWhenF2FCriEnabled()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI));
        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(new VisitedCredentialIssuerDetailsDto(CLAIMED_IDENTITY_CRI, true, null));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(false);
        when(mockConfigService.isEnabled(DRIVING_LICENCE_CRI)).thenReturn(true);
        when(mockConfigService.isEnabled(F2F_CRI)).thenReturn(true);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(MULTIPLE_DOC_CHECK_WITH_F2F_PAGE_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnAddressCriJourneyResponseWhenVisitedClaimedIdentity() throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(new VisitedCredentialIssuerDetailsDto(CLAIMED_IDENTITY_CRI, true, null));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto(CLAIMED_IDENTITY_CRI_ISS, true)));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();
        JourneyResponse response = handleRequest(input, context);

        assertEquals(ADDRESS_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnPyiNoMatchErrorResponseIfClaimedIdentityHasPreviouslyFailed()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(new VisitedCredentialIssuerDetailsDto(CLAIMED_IDENTITY_CRI, false, null));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto(CLAIMED_IDENTITY_CRI_ISS, false)));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();
        JourneyResponse response = handleRequest(input, context);

        assertEquals(PYI_NO_MATCH_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnFraudCriJourneyResponseWhenVisitedClaimedIdentityAndAddress()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI_ISS));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CLAIMED_IDENTITY_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(CLAIMED_IDENTITY_CRI_ISS, true),
                                new VcStatusDto(ADDRESS_CRI_ISS, true)));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();
        JourneyResponse response = handleRequest(input, context);

        assertEquals(FRAUD_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnPyiNoMatchErrorResponseWhenVisitedClaimedIdentityAndAddressFailed()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CLAIMED_IDENTITY_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(CLAIMED_IDENTITY_CRI_ISS, true),
                                new VcStatusDto(ADDRESS_CRI_ISS, false)));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();
        JourneyResponse response = handleRequest(input, context);

        assertEquals(PYI_NO_MATCH_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnF2FCriJourneyResponseWhenVisitedClaimedIdentityAddressAndFraud()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(F2F_CRI))
                .thenReturn(createCriConfig(F2F_CRI_ISS));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CLAIMED_IDENTITY_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(FRAUD_CRI, true, null));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(CLAIMED_IDENTITY_CRI_ISS, true),
                                new VcStatusDto(ADDRESS_CRI_ISS, true),
                                new VcStatusDto(FRAUD_CRI_ISS, true)));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();
        JourneyResponse response = handleRequest(input, context);

        assertEquals(F2F_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnPyiNoMatchErrorResponseWhenVisitedClaimedIdentityAddressAndFraudFailed()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI_ISS));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CLAIMED_IDENTITY_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(FRAUD_CRI, true, null));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(CLAIMED_IDENTITY_CRI_ISS, true),
                                new VcStatusDto(ADDRESS_CRI_ISS, true),
                                new VcStatusDto(FRAUD_CRI_ISS, false)));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();
        JourneyResponse response = handleRequest(input, context);

        assertEquals(PYI_NO_MATCH_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnAddressCriJourneyResponseWhenVisitedPassport() throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto(PASSPORT_CRI_ISS, true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(new VisitedCredentialIssuerDetailsDto(PASSPORT_CRI, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(ADDRESS_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnAddressCriJourneyResponseWhenVisitedDrivingLicence() throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto(PASSPORT_CRI_ISS, true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(new VisitedCredentialIssuerDetailsDto(DRIVING_LICENCE_CRI, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(ADDRESS_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnPyiNoMatchErrorResponseIfAddressCriHasPreviouslyFailed() throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(PASSPORT_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, false, "access_denied"));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(PYI_NO_MATCH_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnFraudCriJourneyResponse() throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI_ISS));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(PASSPORT_CRI_ISS, true),
                                new VcStatusDto(ADDRESS_CRI_ISS, true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(PASSPORT_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(FRAUD_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnKBVCriJourneyResponse() throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(KBV_CRI))
                .thenReturn(createCriConfig(KBV_CRI_ISS));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(PASSPORT_CRI_ISS, true),
                                new VcStatusDto(ADDRESS_CRI_ISS, true),
                                new VcStatusDto(FRAUD_CRI_ISS, true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(PASSPORT_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(FRAUD_CRI, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(KBV_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnJourneyFailedIfAllCriVisited() throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(KBV_CRI))
                .thenReturn(createCriConfig(KBV_CRI_ISS));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(PASSPORT_CRI_ISS, true),
                                new VcStatusDto(ADDRESS_CRI_ISS, true),
                                new VcStatusDto(FRAUD_CRI_ISS, true),
                                new VcStatusDto(KBV_CRI_ISS, true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(PASSPORT_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(FRAUD_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(KBV_CRI, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(FAIL_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserHasNotVisited() throws Exception {
        mockIpvSessionService();

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(DCMAW_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnDcmawSuccessJourneyResponseIfUserHasVisitedDcmawSuccessfully()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto(DCMAW_CRI_ISS, true)));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(List.of(new VisitedCredentialIssuerDetailsDto(DCMAW_CRI, true, null)));

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(DCMAW_SUCCESS_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnFraudCriJourneyResponseIfUserHasVisitedDcmawAndAddressSuccessfully()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI_ISS));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(DCMAW_CRI_ISS, true),
                                new VcStatusDto(ADDRESS_CRI_ISS, true)));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(DCMAW_CRI, true, null),
                                new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null)));
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(FRAUD_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnAddressdCriJourneyResponseIfUserHasNotVistedAppButAlreadyHasPassportVC()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto(PASSPORT_CRI_ISS, true)));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(ADDRESS_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnPyiNoMatchJourneyResponseIfUserHasVisitedDcmawAndAddressAndFraudSuccessfully()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI_ISS));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(DCMAW_CRI_ISS, true),
                                new VcStatusDto(FRAUD_CRI_ISS, true)));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(DCMAW_CRI, true, null),
                                new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null),
                                new VisitedCredentialIssuerDetailsDto(FRAUD_CRI, true, null)));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(DCMAW_CRI_ISS, true),
                                new VcStatusDto(ADDRESS_CRI_ISS, true),
                                new VcStatusDto(FRAUD_CRI_ISS, true)));
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI_ISS));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(FAIL_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserHasVisitedDcmawButItFailedWithAVc()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(List.of(new VisitedCredentialIssuerDetailsDto(DCMAW_CRI, true, null)));
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(UK_PASSPORT_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserHasVisitedDcmawButItFailedWithoutAVc()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(
                                        DCMAW_CRI, false, "access_denied")));
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(UK_PASSPORT_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnPyiNoMatchErrorJourneyResponseIfUserHasAPreviouslyFailedVisitToAddress()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(DCMAW_CRI, true, null),
                                new VisitedCredentialIssuerDetailsDto(
                                        ADDRESS_CRI, false, "access_denied")));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto(DCMAW_CRI_ISS, true)));
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(PYI_NO_MATCH_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnPyiNoMatchErrorJourneyResponseIfUserHasAPreviouslyFailedVisitToDrivingLicence()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(
                                        DRIVING_LICENCE_CRI, true, null)));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto(DRIVING_LICENSE_CRI_ISS, false)));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(PYI_NO_MATCH_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnKbvThinFileErrorJourneyResponseIfUserHasAPreviouslyFailedVisitKbvWithoutCis()
            throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(KBV_CRI))
                .thenReturn(createCriConfig(KBV_CRI_ISS));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(PASSPORT_CRI, true, null),
                                new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null),
                                new VisitedCredentialIssuerDetailsDto(FRAUD_CRI, true, null),
                                new VisitedCredentialIssuerDetailsDto(
                                        KBV_CRI, false, "access_denied")));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto(PASSPORT_CRI_ISS, true),
                                new VcStatusDto(ADDRESS_CRI_ISS, true),
                                new VcStatusDto(FRAUD_CRI_ISS, true),
                                new VcStatusDto(KBV_CRI_ISS, false)));
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(false);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(PYI_KBV_THIN_FILE_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnCorrectJourneyResponseWhenVcStatusesAreNull() throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());
        when(mockIpvSessionItem.getCurrentVcStatuses()).thenReturn(null);

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(false);

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(UK_PASSPORT_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserIsIncludedInAllowedList() throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("false");
        when(mockConfigService.getSsmParameter(DCMAW_ALLOWED_USER_IDS))
                .thenReturn("test-user-id,test-user-id-2,test-user-id-3");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(DCMAW_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserIdHasAppJourneyPrefix() throws Exception {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());
        ClientOAuthSessionItem clientOAuthSessionItem = getClientOAuthSessionItem();
        clientOAuthSessionItem.setUserId(APP_JOURNEY_USER_ID_PREFIX + "some-uuid");
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("false");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(DCMAW_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserIsNotIncludedInAllowedList() throws Exception {
        mockIpvSessionService();

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(createCriConfig(CLAIMED_IDENTITY_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("false");
        when(mockConfigService.getSsmParameter(DCMAW_ALLOWED_USER_IDS))
                .thenReturn("test-user-id,test-user-id-2,test-user-id-3");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI));
        ClientOAuthSessionItem clientOAuthSessionItem = getClientOAuthSessionItem();
        clientOAuthSessionItem.setUserId("test-user-id-4");
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(UK_PASSPORT_JOURNEY, response.getJourney());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfShouldSendAllUsersToAppVarIsTrue() throws Exception {
        mockIpvSessionService();

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI_ISS));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENSE_CRI_ISS));

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn(String.valueOf(true));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = handleRequest(input, context);

        assertEquals(DCMAW_JOURNEY, response.getJourney());
    }

    private void mockIpvSessionService() {
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());
    }

    private JourneyRequest createRequestEvent() {
        return JourneyRequest.builder().ipvSessionId(TEST_SESSION_ID).build();
    }

    private CredentialIssuerConfig createCriConfig(String criIss) throws URISyntaxException {
        return new CredentialIssuerConfig(
                new URI("http://example.com/token"),
                new URI("http://example.com/credential"),
                new URI("http://example.com/authorize"),
                "ipv-core",
                "test-jwk",
                "test-jwk",
                criIss,
                new URI("http://example.com/redirect"),
                true);
    }

    private ClientOAuthSessionItem getClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder()
                .clientOAuthSessionId(SecureTokenHelper.generate())
                .responseType("code")
                .state("test-state")
                .redirectUri("https://example.com/redirect")
                .govukSigninJourneyId("test-journey-id")
                .userId("test-user-id")
                .build();
    }

    private JourneyResponse handleRequest(JourneyRequest event, Context context)
            throws JsonProcessingException {
        var response = underTest.handleRequest(event, context);
        var responseJson =
                objectMapper.writeValueAsString(
                        objectMapper.convertValue(response, new TypeReference<>() {}));
        return objectMapper.readValue(responseJson, JourneyResponse.class);
    }
}
