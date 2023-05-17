package uk.gov.di.ipv.core.credentialissuer;

import com.amazonaws.services.lambda.runtime.Context;
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
import uk.gov.di.ipv.core.selectcri.SelectCriHandler;

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
import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DRIVING_LICENCE_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.FRAUD_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.KBV_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;

@ExtendWith(MockitoExtension.class)
class SelectCriHandlerTest {

    private static final String TEST_SESSION_ID = "the-session-id";
    private static final String APP_JOURNEY_USER_ID_PREFIX = "urn:uuid:app-journey-user-";
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
    void shouldReturnPassportCriJourneyResponse() throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-dcmaw-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("drivingLicence"))
                .thenReturn(createCriConfig("drivingLicence", "drivingLicence", false));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/ukPassport", response.getJourney());
    }

    @Test
    void shouldReturnPassportAndDrivingLicenceCriJourneyResponseWhenDrivingLicenceCriEnabled()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-dcmaw-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("drivingLicence"))
                .thenReturn(createCriConfig("drivingLicence", "drivingLicence", true));
        when(mockConfigService.getActiveConnection("drivingLicence")).thenReturn("main");
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(false);
        when(mockConfigService.isEnabled("drivingLicence")).thenReturn(true);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/ukPassportAndDrivingLicence", response.getJourney());
    }

    @Test
    void shouldReturnAddressCriJourneyResponseWhenVisitedPassport() throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI, "test-address-iss", true));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-passport-iss", true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(new VisitedCredentialIssuerDetailsDto(PASSPORT_CRI, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/address", response.getJourney());
    }

    @Test
    void shouldReturnAddressCriJourneyResponseWhenVisitedDrivingLicence()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI, "test-address-iss", true));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-passport-iss", true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(new VisitedCredentialIssuerDetailsDto(DRIVING_LICENCE_CRI, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/address", response.getJourney());
    }

    @Test
    void shouldReturnPyiNoMatchErrorResponseIfAddressCriHasPreviouslyFailed()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI, "test-driving-licence-iss", true));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(PASSPORT_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, false, "access_denied"));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/pyi-no-match", response.getJourney());
    }

    @Test
    void shouldReturnFraudCriJourneyResponse() throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI, "test-address-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI, "test-fraud-iss", true));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto("test-passport-iss", true),
                                new VcStatusDto("test-address-iss", true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(PASSPORT_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/fraud", response.getJourney());
    }

    @Test
    void shouldReturnKBVCriJourneyResponse() throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI, "test-address-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI, "test-fraud-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(KBV_CRI))
                .thenReturn(createCriConfig(KBV_CRI, "test-kbv-iss", true));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto("test-passport-iss", true),
                                new VcStatusDto("test-address-iss", true),
                                new VcStatusDto("test-fraud-iss", true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(PASSPORT_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(FRAUD_CRI, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/kbv", response.getJourney());
    }

    @Test
    void shouldReturnJourneyFailedIfAllCriVisited() throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI, "test-address-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI, "test-fraud-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(KBV_CRI))
                .thenReturn(createCriConfig(KBV_CRI, "test-kbv-iss", true));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto("test-passport-iss", true),
                                new VcStatusDto("test-address-iss", true),
                                new VcStatusDto("test-fraud-iss", true),
                                new VcStatusDto("test-kbv-iss", true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(PASSPORT_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(FRAUD_CRI, true, null),
                        new VisitedCredentialIssuerDetailsDto(KBV_CRI, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/fail", response.getJourney());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserHasNotVisited() throws URISyntaxException {
        mockIpvSessionService();

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI, "test-driving-licence-iss", true));

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/dcmaw", response.getJourney());
    }

    @Test
    void shouldReturnDcmawSuccessJourneyResponseIfUserHasVisitedDcmawSuccessfully()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI, "test-address-iss", true));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-dcmaw-iss", true)));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(List.of(new VisitedCredentialIssuerDetailsDto("dcmaw", true, null)));

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/dcmaw-success", response.getJourney());
    }

    @Test
    void shouldReturnFraudCriJourneyResponseIfUserHasVisitedDcmawAndAddressSuccessfully()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI, "test-address-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI, "test-fraud-iss", true));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto("test-dcmaw-iss", true),
                                new VcStatusDto("test-address-iss", true)));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(DCMAW_CRI, true, null),
                                new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null)));
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/fraud", response.getJourney());
    }

    @Test
    void shouldReturnAddressdCriJourneyResponseIfUserHasNotVistedAppButAlreadyHasPassportVC()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI, "test-address-iss", true));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-passport-iss", true)));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/address", response.getJourney());
    }

    @Test
    void shouldReturnPyiNoMatchJourneyResponseIfUserHasVisitedDcmawAndAddressAndFraudSuccessfully()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI, "test-fraud-iss", true));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto("test-dcmaw-iss", true),
                                new VcStatusDto("test-fraud-iss", true)));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(DCMAW_CRI, true, null),
                                new VisitedCredentialIssuerDetailsDto(ADDRESS_CRI, true, null),
                                new VisitedCredentialIssuerDetailsDto(FRAUD_CRI, true, null)));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto("test-dcmaw-iss", true),
                                new VcStatusDto("test-address-iss", true),
                                new VcStatusDto("test-fraud-iss", true)));
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI, "test-address-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI, "test-fraud-iss", true));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/fail", response.getJourney());
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserHasVisitedDcmawButItFailedWithAVc()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(List.of(new VisitedCredentialIssuerDetailsDto("dcmaw", true, null)));
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("drivingLicence"))
                .thenReturn(createCriConfig("drivingLicence", "drivingLicence", false));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/ukPassport", response.getJourney());
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserHasVisitedDcmawButItFailedWithoutAVc()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(
                                        "dcmaw", false, "access_denied")));
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("drivingLicence"))
                .thenReturn(createCriConfig("drivingLicence", "drivingLicence", false));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/ukPassport", response.getJourney());
    }

    @Test
    void shouldReturnPyiNoMatchErrorJourneyResponseIfUserHasAPreviouslyFailedVisitToAddress()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI, "test-address-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto("dcmaws", true, null),
                                new VisitedCredentialIssuerDetailsDto(
                                        "address", false, "access_denied")));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-dcmaw-iss", true)));
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/pyi-no-match", response.getJourney());
    }

    @Test
    void shouldReturnPyiNoMatchErrorJourneyResponseIfUserHasAPreviouslyFailedVisitToDrivingLicence()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI, "test-driving-licence-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(
                                        "drivingLicence", true, null)));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-driving-licence-iss", false)));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/pyi-no-match", response.getJourney());
    }

    @Test
    void shouldReturnKbvThinFileErrorJourneyResponseIfUserHasAPreviouslyFailedVisitKbvWithoutCis()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(createCriConfig(ADDRESS_CRI, "test-address-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(FRAUD_CRI))
                .thenReturn(createCriConfig(FRAUD_CRI, "test-fraud-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(KBV_CRI))
                .thenReturn(createCriConfig(KBV_CRI, "test-kbv-iss", true));
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
                                new VcStatusDto("test-address-iss", true),
                                new VcStatusDto("test-fraud-iss", true),
                                new VcStatusDto("test-kbv-iss", false)));
        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(false);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/pyi-kbv-thin-file", response.getJourney());
    }

    @Test
    void shouldReturnCorrectJourneyResponseWhenVcStatusesAreNull() throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());
        when(mockIpvSessionItem.getCurrentVcStatuses()).thenReturn(null);

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(false);

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("drivingLicence"))
                .thenReturn(createCriConfig("drivingLicence", "drivingLicence", false));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/ukPassport", response.getJourney());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserIsIncludedInAllowedList()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI, "test-driving-licence-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("false");
        when(mockConfigService.getSsmParameter(DCMAW_ALLOWED_USER_IDS))
                .thenReturn("test-user-id,test-user-id-2,test-user-id-3");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/dcmaw", response.getJourney());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserIdHasAppJourneyPrefix()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI, "test-driving-licence-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());
        ClientOAuthSessionItem clientOAuthSessionItem = getClientOAuthSessionItem();
        clientOAuthSessionItem.setUserId(APP_JOURNEY_USER_ID_PREFIX + "some-uuid");
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("false");

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/dcmaw", response.getJourney());
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserIsNotIncludedInAllowedList()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("false");
        when(mockConfigService.getSsmParameter(DCMAW_ALLOWED_USER_IDS))
                .thenReturn("test-user-id,test-user-id-2,test-user-id-3");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("drivingLicence"))
                .thenReturn(createCriConfig("drivingLicence", "drivingLicence", false));
        ClientOAuthSessionItem clientOAuthSessionItem = getClientOAuthSessionItem();
        clientOAuthSessionItem.setUserId("test-user-id-4");
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/ukPassport", response.getJourney());
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfShouldSendAllUsersToAppVarIsTrue()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DCMAW_CRI))
                .thenReturn(createCriConfig(DCMAW_CRI, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(PASSPORT_CRI))
                .thenReturn(createCriConfig(PASSPORT_CRI, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(DRIVING_LICENCE_CRI))
                .thenReturn(createCriConfig(DRIVING_LICENCE_CRI, "test-driving-licence-iss", true));

        when(mockConfigService.isEnabled(DCMAW_CRI)).thenReturn(true);
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn(String.valueOf(true));

        JourneyRequest input = createRequestEvent();

        JourneyResponse response = underTest.handleRequest(input, context);

        assertEquals("/journey/dcmaw", response.getJourney());
    }

    private void mockIpvSessionService() {
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());
    }

    private JourneyRequest createRequestEvent() {
        return new JourneyRequest(TEST_SESSION_ID, null, null, null);
    }

    private CredentialIssuerConfig createCriConfig(String criId, String criIss, boolean enabled)
            throws URISyntaxException {
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
}
