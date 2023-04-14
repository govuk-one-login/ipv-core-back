package uk.gov.di.ipv.core.credentialissuer;

import com.amazonaws.services.lambda.runtime.Context;
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
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.selectcri.SelectCriHandler;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ADDRESS_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ALLOWED_USER_IDS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_ENABLED;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DCMAW_SHOULD_SEND_ALL_USERS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.DRIVING_LICENCE_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PASSPORT_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.IPV_SESSION_ID;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.JOURNEY;

@ExtendWith(MockitoExtension.class)
class SelectCriHandlerTest {
    private static final String TEST_SESSION_ID = "the-session-id";
    private static final String CRI_PASSPORT = "ukPassport";
    private static final String CRI_DRIVING_LICENCE = "drivingLicence";
    private static final String CRI_FRAUD = "fraud";
    private static final String CRI_KBV = "kbv";
    private static final String CRI_ADDRESS = "address";
    private static final String CRI_DCMAW = "dcmaw";
    private static final String JOURNEY_ADDRESS = String.format("/journey/%s", CRI_ADDRESS);
    private static final String JOURNEY_DCMAW = String.format("/journey/%s", CRI_DCMAW);
    private static final String JOURNEY_DCMAW_SUCCESS = "/journey/dcmaw-success";
    private static final String JOURNEY_FAIL = "/journey/fail";
    private static final String JOURNEY_FRAUD = String.format("/journey/%s", CRI_FRAUD);
    private static final String JOURNEY_KBV = String.format("/journey/%s", CRI_KBV);
    private static final String JOURNEY_PYI_NOMATCH = "/journey/pyi-no-match";
    private static final String JOURNEY_PYI_THIN_FILE = "/journey/pyi-kbv-thin-file";
    private static final String JOURNEY_UKPASSPORT = String.format("/journey/%s", CRI_PASSPORT);
    private static final String APP_JOURNEY_USER_ID_PREFIX = "urn:uuid:app-journey-user-";

    @Mock private Context context;
    @Mock private ConfigService mockConfigService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @Mock private ClientSessionDetailsDto mockClientSessionDetailsDto;

    private SelectCriHandler underTest;

    @BeforeEach
    void setUp() {
        mockConfigurationServiceMethodCalls();

        underTest = new SelectCriHandler(mockConfigService, mockIpvSessionService);
    }

    @Test
    void shouldReturnPassportCriJourneyResponse()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-dcmaw-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("drivingLicence"))
                .thenReturn(createCriConfig("drivingLicence", "drivingLicence", false));

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_UKPASSPORT, response.get(JOURNEY));
    }

    @Test
    void shouldReturnPassportAndDrivingLicenceCriJourneyResponseWhenDrivingLicenceCriEnabled()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-dcmaw-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("drivingLicence"))
                .thenReturn(createCriConfig("drivingLicence", "drivingLicence", true));

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_UKPASSPORT, response.get(JOURNEY));
    }

    @Test
    void shouldReturnAddressCriJourneyResponseWhenVisitedPassport() throws URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DRIVING_LICENCE))
                .thenReturn(createCriConfig(CRI_DRIVING_LICENCE, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_ADDRESS))
                .thenReturn(createCriConfig(CRI_ADDRESS, "test-address-iss", true));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-passport-iss", true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_ADDRESS, response.get(JOURNEY));
    }

    @Test
    void shouldReturnAddressCriJourneyResponseWhenVisitedDrivingLicence() throws URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DRIVING_LICENCE))
                .thenReturn(createCriConfig(CRI_DRIVING_LICENCE, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_ADDRESS))
                .thenReturn(createCriConfig(CRI_ADDRESS, "test-address-iss", true));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-passport-iss", true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(new VisitedCredentialIssuerDetailsDto(CRI_DRIVING_LICENCE, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_ADDRESS, response.get(JOURNEY));
    }

    @Test
    void shouldReturnPyiNoMatchErrorResponseIfAddressCriHasPreviouslyFailed() throws URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DRIVING_LICENCE))
                .thenReturn(createCriConfig(CRI_DRIVING_LICENCE, "test-driving-licence-iss", true));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, false, "access_denied"));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_PYI_NOMATCH, response.get(JOURNEY));
    }

    @Test
    void shouldReturnFraudCriJourneyResponse() throws URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DRIVING_LICENCE))
                .thenReturn(createCriConfig(CRI_DRIVING_LICENCE, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_ADDRESS))
                .thenReturn(createCriConfig(CRI_ADDRESS, "test-address-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss", true));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto("test-passport-iss", true),
                                new VcStatusDto("test-address-iss", true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_FRAUD, response.get(JOURNEY));
    }

    @Test
    void shouldReturnKBVCriJourneyResponse() throws URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DRIVING_LICENCE))
                .thenReturn(createCriConfig(CRI_DRIVING_LICENCE, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_ADDRESS))
                .thenReturn(createCriConfig(CRI_ADDRESS, "test-address-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_KBV))
                .thenReturn(createCriConfig(CRI_KBV, "test-kbv-iss", true));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto("test-passport-iss", true),
                                new VcStatusDto("test-address-iss", true),
                                new VcStatusDto("test-fraud-iss", true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_FRAUD, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_KBV, response.get(JOURNEY));
    }

    @Test
    void shouldReturnJourneyFailedIfAllCriVisited() throws URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DRIVING_LICENCE))
                .thenReturn(createCriConfig(CRI_DRIVING_LICENCE, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_ADDRESS))
                .thenReturn(createCriConfig(CRI_ADDRESS, "test-address-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_KBV))
                .thenReturn(createCriConfig(CRI_KBV, "test-kbv-iss", true));

        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto("test-passport-iss", true),
                                new VcStatusDto("test-address-iss", true),
                                new VcStatusDto("test-fraud-iss", true),
                                new VcStatusDto("test-kbv-iss", true)));

        List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
                List.of(
                        new VisitedCredentialIssuerDetailsDto(CRI_PASSPORT, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_FRAUD, true, null),
                        new VisitedCredentialIssuerDetailsDto(CRI_KBV, true, null));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(visitedCredentialIssuerDetails);

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_FAIL, response.get(JOURNEY));
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserHasNotVisited() throws URISyntaxException {
        mockIpvSessionService();

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DRIVING_LICENCE))
                .thenReturn(createCriConfig(CRI_DRIVING_LICENCE, "test-driving-licence-iss", true));

        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_DCMAW, response.get(JOURNEY));
    }

    @Test
    void shouldReturnDcmawSuccessJourneyResponseIfUserHasVisitedDcmawSuccessfully() throws URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_ADDRESS))
                .thenReturn(createCriConfig(CRI_ADDRESS, "test-address-iss", true));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-dcmaw-iss", true)));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(List.of(new VisitedCredentialIssuerDetailsDto("dcmaw", true, null)));

        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_DCMAW_SUCCESS, response.get(JOURNEY));
    }

    @Test
    void shouldReturnFraudCriJourneyResponseIfUserHasVisitedDcmawAndAddressSuccessfully() throws URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_ADDRESS))
                .thenReturn(createCriConfig(CRI_ADDRESS, "test-address-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss", true));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(
                        List.of(
                                new VcStatusDto("test-dcmaw-iss", true),
                                new VcStatusDto("test-address-iss", true)));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(CRI_DCMAW, true, null),
                                new VisitedCredentialIssuerDetailsDto(CRI_ADDRESS, true, null)));

        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_FRAUD, response.get(JOURNEY));
    }

    @Test
    void shouldReturnAddressdCriJourneyResponseIfUserHasNotVistedAppButAlreadyHasPassportVC()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DRIVING_LICENCE))
                .thenReturn(createCriConfig(CRI_DRIVING_LICENCE, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_ADDRESS))
                .thenReturn(createCriConfig(CRI_ADDRESS, "test-address-iss", true));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-passport-iss", true)));

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_ADDRESS, response.get(JOURNEY));
    }

    @Test
    void shouldReturnPyiNoMatchJourneyResponseIfUserHasVisitedDcmawAndAddressAndFraudSuccessfully()
            throws URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss", true));
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

        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_ADDRESS))
                .thenReturn(createCriConfig(CRI_ADDRESS, "test-address-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss", true));

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_FAIL, response.get(JOURNEY));
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserHasVisitedDcmawButItFailedWithAVc() throws URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(List.of(new VisitedCredentialIssuerDetailsDto("dcmaw", true, null)));
        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("drivingLicence"))
                .thenReturn(createCriConfig("drivingLicence", "drivingLicence", false));

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_UKPASSPORT, response.get(JOURNEY));
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserHasVisitedDcmawButItFailedWithoutAVc() throws URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(
                                        "dcmaw", false, "access_denied")));

        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("drivingLicence"))
                .thenReturn(createCriConfig("drivingLicence", "drivingLicence", false));

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_UKPASSPORT, response.get(JOURNEY));
    }

    @Test
    void shouldReturnPyiNoMatchErrorJourneyResponseIfUserHasAPreviouslyFailedVisitToAddress()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_ADDRESS))
                .thenReturn(createCriConfig(CRI_ADDRESS, "test-address-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto("dcmaws", true, null),
                                new VisitedCredentialIssuerDetailsDto(
                                        "address", false, "access_denied")));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-dcmaw-iss", true)));

        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("true");

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_PYI_NOMATCH, response.get(JOURNEY));
    }

    @Test
    void shouldReturnPyiNoMatchErrorJourneyResponseIfUserHasAPreviouslyFailedVisitToDrivingLicence()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DRIVING_LICENCE))
                .thenReturn(createCriConfig(CRI_DRIVING_LICENCE, "test-driving-licence-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(
                        List.of(
                                new VisitedCredentialIssuerDetailsDto(
                                        "drivingLicence", true, null)));
        when(mockIpvSessionItem.getCurrentVcStatuses())
                .thenReturn(List.of(new VcStatusDto("test-driving-licence-iss", false)));

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_PYI_NOMATCH, response.get(JOURNEY));
    }

    @Test
    void shouldReturnKbvThinFileErrorJourneyResponseIfUserHasAPreviouslyFailedVisitKbvWithoutCis()
            throws URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DRIVING_LICENCE))
                .thenReturn(createCriConfig(CRI_DRIVING_LICENCE, "test-driving-licence-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_ADDRESS))
                .thenReturn(createCriConfig(CRI_ADDRESS, "test-address-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_FRAUD))
                .thenReturn(createCriConfig(CRI_FRAUD, "test-fraud-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_KBV))
                .thenReturn(createCriConfig(CRI_KBV, "test-kbv-iss", true));
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

        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("false");

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_PYI_THIN_FILE, response.get(JOURNEY));
    }

    @Test
    void shouldReturnCorrectJourneyResponseWhenVcStatusesAreNull() throws URISyntaxException {
        mockIpvSessionService();

        when(mockClientSessionDetailsDto.getUserId()).thenReturn("test-user-id");
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());
        when(mockIpvSessionItem.getCurrentVcStatuses()).thenReturn(null);

        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("false");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("drivingLicence"))
                .thenReturn(createCriConfig("drivingLicence", "drivingLicence", false));

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_UKPASSPORT, response.get(JOURNEY));
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserIsIncludedInAllowedList() throws URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DRIVING_LICENCE))
                .thenReturn(createCriConfig(CRI_DRIVING_LICENCE, "test-driving-licence-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("false");
        when(mockConfigService.getSsmParameter(DCMAW_ALLOWED_USER_IDS))
                .thenReturn("test-user-id,test-user-id-2,test-user-id-3");

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_DCMAW, response.get(JOURNEY));
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfUserIdHasAppJourneyPrefix() throws URISyntaxException {
        mockIpvSessionService();

        String userId = APP_JOURNEY_USER_ID_PREFIX + "some-uuid";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DRIVING_LICENCE))
                .thenReturn(createCriConfig(CRI_DRIVING_LICENCE, "test-driving-licence-iss", true));
        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("false");

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_DCMAW, response.get(JOURNEY));
    }

    @Test
    void shouldReturnPassportCriJourneyResponseIfUserIsNotIncludedInAllowedList() throws URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id-4";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));

        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS)).thenReturn("false");
        when(mockConfigService.getSsmParameter(DCMAW_ALLOWED_USER_IDS))
                .thenReturn("test-user-id,test-user-id-2,test-user-id-3");

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig("drivingLicence"))
                .thenReturn(createCriConfig("drivingLicence", "drivingLicence", false));

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_UKPASSPORT, response.get(JOURNEY));
    }

    @Test
    void shouldReturnDcmawCriJourneyResponseIfShouldSendAllUsersToAppVarIsTrue() throws URISyntaxException {
        mockIpvSessionService();

        String userId = "test-user-id";
        when(mockClientSessionDetailsDto.getUserId()).thenReturn(userId);

        when(mockIpvSessionItem.getVisitedCredentialIssuerDetails())
                .thenReturn(Collections.emptyList());

        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DCMAW))
                .thenReturn(createCriConfig(CRI_DCMAW, "test-dcmaw-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_PASSPORT))
                .thenReturn(createCriConfig(CRI_PASSPORT, "test-passport-iss", true));
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(CRI_DRIVING_LICENCE))
                .thenReturn(createCriConfig(CRI_DRIVING_LICENCE, "test-driving-licence-iss", true));

        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("true");
        when(mockConfigService.getSsmParameter(DCMAW_SHOULD_SEND_ALL_USERS))
                .thenReturn(String.valueOf(true));

        var input = createRequestEvent();

        var response = underTest.handleRequest(input, context);

        assertNotNull(response);
        assertEquals(JOURNEY_DCMAW, response.get(JOURNEY));
    }

    private void mockIpvSessionService() {

        when(mockIpvSessionItem.getClientSessionDetails()).thenReturn(mockClientSessionDetailsDto);
        when(mockIpvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(mockIpvSessionItem);
    }

    private void mockConfigurationServiceMethodCalls() {
        when(mockConfigService.getSsmParameter(PASSPORT_CRI_ID)).thenReturn(CRI_PASSPORT);
        when(mockConfigService.getSsmParameter(FRAUD_CRI_ID)).thenReturn(CRI_FRAUD);
        when(mockConfigService.getSsmParameter(KBV_CRI_ID)).thenReturn(CRI_KBV);
        when(mockConfigService.getSsmParameter(ADDRESS_CRI_ID)).thenReturn(CRI_ADDRESS);
        when(mockConfigService.getSsmParameter(DRIVING_LICENCE_CRI_ID))
                .thenReturn("drivingLicence");
        when(mockConfigService.getSsmParameter(DCMAW_CRI_ID)).thenReturn(CRI_DCMAW);
        when(mockConfigService.getSsmParameter(DCMAW_ENABLED)).thenReturn("false");
    }

    private Map<String, String> createRequestEvent() {
        return Map.of(IPV_SESSION_ID, TEST_SESSION_ID);
    }

    private CredentialIssuerConfig createCriConfig(String criId, String criIss, boolean enabled)
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
}
