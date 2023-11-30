package uk.gov.di.ipv.core.evaluategpg45scores;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionGpg45ProfileMatched;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.evaluategpg45scores.EvaluateGpg45ScoresHandler.VOT_P2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_VERIFICATION_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M2B;

@ExtendWith(MockitoExtension.class)
class EvaluateGpg45ScoresHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static JourneyRequest request;
    private static final List<String> CREDENTIALS =
            List.of(
                    M1A_PASSPORT_VC,
                    M1A_ADDRESS_VC,
                    M1A_FRAUD_VC,
                    M1A_VERIFICATION_VC,
                    M1B_DCMAW_VC);
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";
    public static CredentialIssuerConfig addressConfig = null;
    public static CredentialIssuerConfig claimedIdentityConfig = null;
    private static final List<SignedJWT> PARSED_CREDENTIALS = new ArrayList<>();
    private static final List<Gpg45Profile> ACCEPTED_PROFILES = List.of(M1A, M1B, M2B);
    private static final JourneyResponse JOURNEY_END = new JourneyResponse("/journey/end");
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse("/journey/next");
    private static final String JOURNEY_PYI_NO_MATCH = "/journey/pyi-no-match";
    private static final String JOURNEY_FAIL_WITH_NO_CI = "/journey/fail-with-no-ci";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.generate();
    private static final ObjectMapper mapper = new ObjectMapper();

    static {
        try {
            addressConfig =
                    CredentialIssuerConfig.builder()
                            .tokenUrl(new URI("http://example.com/token"))
                            .credentialUrl(new URI("http://example.com/credential"))
                            .authorizeUrl(new URI("http://example.com/authorize"))
                            .clientId("ipv-core")
                            .signingKey("test-jwk")
                            .encryptionKey("test-encryption-jwk")
                            .componentId("https://review-a.integration.account.gov.uk")
                            .clientCallbackUrl(new URI("http://example.com/redirect"))
                            .requiresApiKey(true)
                            .requiresAdditionalEvidence(false)
                            .build();

            claimedIdentityConfig =
                    CredentialIssuerConfig.builder()
                            .tokenUrl(new URI("http://example.com/token"))
                            .credentialUrl(new URI("http://example.com/credential"))
                            .authorizeUrl(new URI("http://example.com/authorize"))
                            .clientId("ipv-core")
                            .signingKey("test-jwk")
                            .encryptionKey("test-encryption-jwk")
                            .componentId("https://review-a.integration.account.gov.uk")
                            .clientCallbackUrl(new URI("http://example.com/redirect"))
                            .requiresApiKey(true)
                            .requiresAdditionalEvidence(false)
                            .build();

        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @Mock private ConfigService configService;
    @Mock private AuditService auditService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @InjectMocks private EvaluateGpg45ScoresHandler evaluateGpg45ScoresHandler;

    @Spy private IpvSessionItem ipvSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeAll
    static void setUp() throws Exception {
        request =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_CLIENT_SOURCE_IP)
                        .build();
        for (String cred : CREDENTIALS) {
            PARSED_CREDENTIALS.add(SignedJWT.parse(cred));
        }
    }

    @BeforeEach
    void setUpEach() {
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setIpvSessionId(TEST_SESSION_ID);
        ipvSessionItem.setVisitedCredentialIssuerDetails(
                List.of(
                        new VisitedCredentialIssuerDetailsDto(
                                "criId",
                                "https://review-a.integration.account.gov.uk",
                                true,
                                null)));

        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .state("test-state")
                        .responseType("code")
                        .redirectUri("https://example.com/redirect")
                        .govukSigninJourneyId("test-journey-id")
                        .userId(TEST_USER_ID)
                        .clientId("test-client")
                        .govukSigninJourneyId(TEST_JOURNEY_ID)
                        .build();
    }

    @Test
    void shouldReturnJourneySessionEndIfScoresSatisfyM1AGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_END.getJourney(), response.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(VOT_P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(VOT_P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneySessionEndIfScoresSatisfyM1BGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(gpg45ProfileEvaluator.buildScore(any())).thenReturn(new Gpg45Scores(1, 1, 1, 1, 1));
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_END.getJourney(), response.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(VOT_P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(VOT_P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyNextIfScoresDoNotSatisfyM1AGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 0));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_NEXT.getJourney(), response.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyNextIfGpg45ProfileNotMatched() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_NEXT.getJourney(), response.getJourney());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn400IfSessionIdNotInRequest() {
        JourneyRequest requestWithoutSessionId =
                JourneyRequest.builder().ipAddress(TEST_CLIENT_SOURCE_IP).build();

        JourneyErrorResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(requestWithoutSessionId, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), response.getCode());
        verify(clientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfFailedToParseCredentials() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(gpg45ProfileEvaluator.buildScore(any())).thenThrow(new ParseException("Whoops", 0));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyErrorResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode(), response.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(),
                response.getMessage());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfCredentialOfUnknownType() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(gpg45ProfileEvaluator.buildScore(any())).thenThrow(new UnknownEvidenceTypeException());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyErrorResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getCode(), response.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getMessage(),
                response.getMessage());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnFailWithNoCiJourneyResponseIfLastVcStatusesUnsuccessful() throws Exception {
        IpvSessionItem testIpvSessionItem = new IpvSessionItem();
        testIpvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        testIpvSessionItem.setIpvSessionId(TEST_SESSION_ID);
        testIpvSessionItem.setVisitedCredentialIssuerDetails(
                List.of(
                        new VisitedCredentialIssuerDetailsDto(
                                "criIdB",
                                "https://review-b.integration.account.gov.uk",
                                true,
                                null),
                        new VisitedCredentialIssuerDetailsDto(
                                "criIdC",
                                "https://review-c.integration.account.gov.uk",
                                true,
                                null),
                        new VisitedCredentialIssuerDetailsDto(
                                "criIdA",
                                "https://review-a.integration.account.gov.uk",
                                true,
                                null)));

        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(testIpvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(userIdentityService.getVCSuccessStatus(TEST_USER_ID, "criIdA"))
                .thenReturn(Optional.of(false));
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_FAIL_WITH_NO_CI, response.getJourney());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfNoVisitedCredentialIssuersFound() throws Exception {
        IpvSessionItem testIpvSessionItem = new IpvSessionItem();
        testIpvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        testIpvSessionItem.setIpvSessionId(TEST_SESSION_ID);
        testIpvSessionItem.setVisitedCredentialIssuerDetails(List.of());

        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(testIpvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyErrorResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_FIND_VISITED_CRI.getCode(), response.getCode());
        assertEquals(ErrorResponse.FAILED_TO_FIND_VISITED_CRI.getMessage(), response.getMessage());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldSendAuditEventWhenProfileMatched() throws Exception {
        List<SignedJWT> parsedM1ACreds =
                List.of(
                        SignedJWT.parse(M1A_PASSPORT_VC),
                        SignedJWT.parse(M1A_ADDRESS_VC),
                        SignedJWT.parse(M1A_FRAUD_VC),
                        SignedJWT.parse(M1A_VERIFICATION_VC));
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(parsedM1ACreds);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 2));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        evaluateGpg45ScoresHandler.handleRequest(request, context);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService).sendAuditEvent(auditEventCaptor.capture());
        AuditEvent auditEvent = auditEventCaptor.getValue();

        assertEquals(AuditEventTypes.IPV_GPG45_PROFILE_MATCHED, auditEvent.getEventName());

        AuditEventUser user = auditEvent.getUser();
        assertEquals(TEST_USER_ID, user.getUserId());
        assertEquals(TEST_JOURNEY_ID, user.getGovukSigninJourneyId());
        assertEquals(TEST_SESSION_ID, user.getSessionId());

        AuditExtensionGpg45ProfileMatched extension =
                (AuditExtensionGpg45ProfileMatched) auditEvent.getExtensions();
        assertEquals(M1A, extension.getGpg45Profile());
        assertEquals(new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 2), extension.getGpg45Scores());
        assertEquals(
                List.of("123ab93d-3a43-46ef-a2c1-3c6444206408", "RB000103490087", "abc1234"),
                extension.getVcTxnIds());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(VOT_P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(VOT_P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnPyiNoMatchIfFailedDueToNameCorrelationIssues() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any()))
                .thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_PYI_NO_MATCH, response.getJourney());

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(userIdentityService, times(1)).checkNameAndFamilyNameCorrelationInCredentials(any());
        verify(userIdentityService, times(0)).checkBirthDateCorrelationInCredentials(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void
            shouldReturn500IfCredentialParseExceptionFromCheckNameAndFamilyNameCorrelationInCredentials()
                    throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any()))
                .thenThrow(
                        new CredentialParseException("Failed to parse successful VC Store items."));

        JourneyErrorResponse journeyResponse =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, journeyResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getCode(),
                journeyResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getMessage(),
                journeyResponse.getMessage());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfCredentialParseExceptionFromCheckBirthDateCorrelationInCredentials()
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any()))
                .thenThrow(
                        new CredentialParseException("Failed to parse successful VC Store items."));

        JourneyErrorResponse journeyResponse =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, journeyResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getCode(),
                journeyResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getMessage(),
                journeyResponse.getMessage());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyNextIfCheckRequiresAdditionalEvidenceResponseTrue() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any())).thenReturn(true);

        when(userIdentityService.checkRequiresAdditionalEvidence(TEST_USER_ID)).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_NEXT.getJourney(), response.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        verify(userIdentityService, times(1)).checkRequiresAdditionalEvidence(TEST_USER_ID);
    }

    @Test
    void shouldReturnJourneyNextIfCheckRequiresAdditionalEvidenceResponseFalse() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any())).thenReturn(true);

        when(userIdentityService.checkRequiresAdditionalEvidence(TEST_USER_ID)).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_END.getJourney(), response.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(VOT_P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(VOT_P2, ipvSessionItem.getVot());
        verify(userIdentityService, times(1)).checkRequiresAdditionalEvidence(TEST_USER_ID);
    }

    private <T> T toResponseClass(Map<String, Object> handlerOutput, Class<T> responseClass) {
        return mapper.convertValue(handlerOutput, responseClass);
    }
}
