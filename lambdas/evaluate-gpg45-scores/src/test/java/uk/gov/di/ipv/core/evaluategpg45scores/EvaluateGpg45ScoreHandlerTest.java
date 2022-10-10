package uk.gov.di.ipv.core.evaluategpg45scores;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FAILED_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_VERIFICATION_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IPV_SESSION_ID_HEADER;

@ExtendWith(MockitoExtension.class)
class EvaluateGpg45ScoreHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
    public static final List<String> CREDENTIALS =
            List.of(
                    M1A_PASSPORT_VC,
                    M1A_ADDRESS_VC,
                    M1A_FRAUD_VC,
                    M1A_VERIFICATION_VC,
                    M1B_DCMAW_VC);
    public static final List<String> FAILED_PASSPORT_CREDENTIALS =
            List.of(
                    M1A_FAILED_PASSPORT_VC,
                    M1A_ADDRESS_VC,
                    M1A_FRAUD_VC,
                    M1A_VERIFICATION_VC,
                    M1B_DCMAW_VC);
    public static final Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>>
            EVIDENCE_MAP = generateEvidenceMap();
    public static CredentialIssuerConfig addressConfig = null;

    static {
        try {
            addressConfig =
                    new CredentialIssuerConfig(
                            "address",
                            "address",
                            new URI("http://example.com/token"),
                            new URI("http://example.com/credential"),
                            new URI("http://example.com/authorize"),
                            "ipv-core",
                            "test-jwk",
                            "test-encryption-jwk",
                            "test-audience",
                            new URI("http://example.com/redirect"));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @Mock private CiStorageService ciStorageService;
    @Mock private ConfigurationService configurationService;
    @InjectMocks private EvaluateGpg45ScoresHandler evaluateGpg45ScoresHandler;

    private final Gson gson = new Gson();

    private IpvSessionItem ipvSessionItem;

    @BeforeAll
    static void setUp() {
        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER, TEST_SESSION_ID));
    }

    @BeforeEach
    void setUpEach() {
        ipvSessionItem = new IpvSessionItem();
        ClientSessionDetailsDto clientSessionDetailsDto = new ClientSessionDetailsDto();
        clientSessionDetailsDto.setUserId(TEST_USER_ID);
        clientSessionDetailsDto.setGovukSigninJourneyId(TEST_JOURNEY_ID);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
    }

    //    @Test
    //    void shouldReturnJourneySessionEndIfScoresSatisfyM1AGpg45Profile() throws Exception {
    //        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
    //                Map.of(
    //                        CredentialEvidenceItem.EvidenceType.ACTIVITY,
    //                        new ArrayList<>(),
    //                        CredentialEvidenceItem.EvidenceType.EVIDENCE,
    //                        Collections.singletonList(
    //                                new CredentialEvidenceItem(4, 2, Collections.emptyList())),
    //                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
    //                        Collections.singletonList(
    //                                new CredentialEvidenceItem(
    //                                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
    //                                        2,
    //                                        Collections.emptyList())),
    //                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
    //                        Collections.singletonList(
    //                                new CredentialEvidenceItem(
    //                                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
    //                                        2,
    //                                        Collections.emptyList())),
    //                        CredentialEvidenceItem.EvidenceType.DCMAW,
    //                        new ArrayList<>());
    //
    //        when(configurationService.getCredentialIssuer(any())).thenReturn(addressConfig);
    //        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
    //
    // when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
    //        when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(CREDENTIALS))
    //                .thenReturn(evidenceMap);
    //        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
    //                .thenReturn(Optional.empty());
    //        when(gpg45ProfileEvaluator.credentialsSatisfyAnyProfile(evidenceMap,
    // ACCEPTED_PROFILES))
    //                .thenReturn(true);
    //
    //        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
    //        JourneyResponse journeyResponse = gson.fromJson(response.getBody(),
    // JourneyResponse.class);
    //
    //        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    //        assertEquals(JOURNEY_END, journeyResponse);
    //        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    //    }
    //
    //    @Test
    //    void shouldReturnJourneySessionEndIfScoresSatisfyM1BGpg45Profile() throws Exception {
    //        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
    //                Map.of(
    //                        CredentialEvidenceItem.EvidenceType.ACTIVITY, new ArrayList<>(),
    //                        CredentialEvidenceItem.EvidenceType.EVIDENCE, new ArrayList<>(),
    //                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
    //                                Collections.singletonList(
    //                                        new CredentialEvidenceItem(
    //
    // CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
    //                                                2,
    //                                                Collections.emptyList())),
    //                        CredentialEvidenceItem.EvidenceType.VERIFICATION, new ArrayList<>(),
    //                        CredentialEvidenceItem.EvidenceType.DCMAW,
    //                                Collections.singletonList(
    //                                        new CredentialEvidenceItem(
    //                                                3,
    //                                                2,
    //                                                1,
    //                                                2,
    //                                                Collections.singletonList(new
    // DcmawCheckMethod()),
    //                                                null,
    //                                                Collections.emptyList())));
    //
    //        when(configurationService.getCredentialIssuer(any())).thenReturn(addressConfig);
    //        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
    //
    // when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
    //        when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(CREDENTIALS))
    //                .thenReturn(evidenceMap);
    //        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
    //                .thenReturn(Optional.empty());
    //        when(gpg45ProfileEvaluator.credentialsSatisfyAnyProfile(evidenceMap,
    // ACCEPTED_PROFILES))
    //                .thenReturn(true);
    //
    //        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
    //        JourneyResponse journeyResponse = gson.fromJson(response.getBody(),
    // JourneyResponse.class);
    //
    //        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    //        assertEquals(JOURNEY_END, journeyResponse);
    //        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    //    }
    //
    //    @Test
    //    void shouldReturnJourneyNextIfScoresDoNotSatisfyM1AGpg45Profile() throws Exception {
    //        when(configurationService.getCredentialIssuer(any())).thenReturn(addressConfig);
    //        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
    //
    // when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
    //        when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(CREDENTIALS))
    //                .thenReturn(EVIDENCE_MAP);
    //        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
    //                .thenReturn(Optional.empty());
    //        when(gpg45ProfileEvaluator.credentialsSatisfyAnyProfile(EVIDENCE_MAP,
    // ACCEPTED_PROFILES))
    //                .thenReturn(false);
    //
    //        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
    //        JourneyResponse journeyResponse = gson.fromJson(response.getBody(),
    // JourneyResponse.class);
    //
    //        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    //        assertEquals(JOURNEY_NEXT, journeyResponse);
    //        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    //    }
    //
    //    @Test
    //    void
    // shouldReturnJourneyNextIfScoresDoNotSatisfyM1AGpg45ProfileAndPassportScoresAreNotValid()
    //            throws Exception {
    //        when(configurationService.getCredentialIssuer(any())).thenReturn(addressConfig);
    //        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
    //        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID))
    //                .thenReturn(FAILED_PASSPORT_CREDENTIALS);
    //
    // when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(FAILED_PASSPORT_CREDENTIALS))
    //                .thenReturn(EVIDENCE_MAP);
    //        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
    //                .thenReturn(Optional.empty());
    //        when(gpg45ProfileEvaluator.credentialsSatisfyAnyProfile(EVIDENCE_MAP,
    // ACCEPTED_PROFILES))
    //                .thenReturn(false);
    //
    //        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
    //        JourneyResponse journeyResponse = gson.fromJson(response.getBody(),
    // JourneyResponse.class);
    //
    //        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    //        assertEquals(JOURNEY_NEXT, journeyResponse);
    //        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    //    }
    //
    //    @Test
    //    void shouldReturn400IfSessionIdNotInHeader() {
    //        APIGatewayProxyRequestEvent eventWithoutHeaders = new APIGatewayProxyRequestEvent();
    //
    //        var response = evaluateGpg45ScoresHandler.handleRequest(eventWithoutHeaders, context);
    //        var error = gson.fromJson(response.getBody(), Map.class);
    //
    //        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    //        assertEquals(
    //                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(),
    // error.get("error_description"));
    //    }
    //
    //    @Test
    //    void shouldReturn500IfFailedToParseCredentials() throws Exception {
    //        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
    //
    // when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
    //        when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(CREDENTIALS))
    //                .thenThrow(new ParseException("Whoops", 0));
    //
    //        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
    //        Map<String, Object> responseMap =
    //                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
    //
    //        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
    //        assertEquals(
    //                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode(),
    //                responseMap.get("code"));
    //        assertEquals(
    //                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(),
    //                responseMap.get("message"));
    //        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    //    }
    //
    //    @Test
    //    void shouldReturn500IfCredentialOfUnknownType() throws Exception {
    //        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
    //
    // when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
    //        when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(CREDENTIALS))
    //                .thenReturn(EVIDENCE_MAP);
    //        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
    //                .thenReturn(Optional.empty());
    //        when(gpg45ProfileEvaluator.credentialsSatisfyAnyProfile(EVIDENCE_MAP,
    // ACCEPTED_PROFILES))
    //                .thenThrow(new UnknownEvidenceTypeException());
    //
    //        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
    //        Map<String, Object> responseMap =
    //                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
    //
    //        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
    //        assertEquals(
    //                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getCode(),
    //                responseMap.get("code"));
    //        assertEquals(
    //                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getMessage(),
    //                responseMap.get("message"));
    //        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    //    }
    //
    //    @Test
    //    void shouldReturnJourneyErrorJourneyResponseIfCiAreFoundOnVcs() throws Exception {
    //        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
    //
    // when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
    //        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(
    //                        ipvSessionItem.getClientSessionDetails()))
    //                .thenReturn(Optional.of(new JourneyResponse("/journey/pyi-no-match")));
    //
    //        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
    //        JourneyResponse journeyResponse = gson.fromJson(response.getBody(),
    // JourneyResponse.class);
    //
    //        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    //        assertEquals("/journey/pyi-no-match", journeyResponse.getJourney());
    //    }
    //
    //    @Test
    //    void shouldReturn500IfFailedToRetrieveCisFromStorageSystem() throws Exception {
    //        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
    //
    // when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
    //        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(
    //                        ipvSessionItem.getClientSessionDetails()))
    //                .thenThrow(CiRetrievalException.class);
    //
    //        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
    //
    //        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
    //        Map<String, Object> responseMap =
    //                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
    //
    //        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
    //        assertEquals(ErrorResponse.FAILED_TO_GET_STORED_CIS.getCode(),
    // responseMap.get("code"));
    //        assertEquals(
    //                ErrorResponse.FAILED_TO_GET_STORED_CIS.getMessage(),
    // responseMap.get("message"));
    //    }

    private static Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>>
            generateEvidenceMap() {
        return Map.of(
                CredentialEvidenceItem.EvidenceType.ACTIVITY, new ArrayList<>(),
                CredentialEvidenceItem.EvidenceType.EVIDENCE,
                        Collections.singletonList(
                                new CredentialEvidenceItem(4, 2, Collections.emptyList())),
                CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, new ArrayList<>(),
                CredentialEvidenceItem.EvidenceType.VERIFICATION, new ArrayList<>(),
                CredentialEvidenceItem.EvidenceType.DCMAW, new ArrayList<>());
    }
}
