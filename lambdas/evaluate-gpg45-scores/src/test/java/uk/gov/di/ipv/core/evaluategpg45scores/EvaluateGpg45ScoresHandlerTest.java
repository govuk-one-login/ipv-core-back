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
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

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
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.EXPERIAN_FRAUD_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.EXPERIAN_KBV_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.HMRC_MIGRATION_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_VERIFICATION_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_INHERITED_IDENTITY_MIGRATION_WITH_NO_EVIDENCE;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M2B;

@ExtendWith(MockitoExtension.class)
class EvaluateGpg45ScoresHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static JourneyRequest request;
    private static final List<VcStoreItem> VC_STORE_ITEMS =
            List.of(
                    TestFixtures.createVcStoreItem(TEST_USER_ID, PASSPORT_CRI, M1A_PASSPORT_VC),
                    TestFixtures.createVcStoreItem(TEST_USER_ID, ADDRESS_CRI, M1A_ADDRESS_VC),
                    TestFixtures.createVcStoreItem(
                            TEST_USER_ID, EXPERIAN_FRAUD_CRI, M1A_EXPERIAN_FRAUD_VC),
                    TestFixtures.createVcStoreItem(
                            TEST_USER_ID, EXPERIAN_KBV_CRI, M1A_VERIFICATION_VC),
                    TestFixtures.createVcStoreItem(TEST_USER_ID, DCMAW_CRI, M1B_DCMAW_VC),
                    TestFixtures.createVcStoreItem(
                            TEST_USER_ID, HMRC_MIGRATION_CRI, VC_HMRC_MIGRATION));
    private static final List<String> CREDENTIALS =
            List.of(
                    M1A_PASSPORT_VC,
                    M1A_ADDRESS_VC,
                    M1A_EXPERIAN_FRAUD_VC,
                    M1A_VERIFICATION_VC,
                    M1B_DCMAW_VC);
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";
    public static OauthCriConfig addressConfig = null;
    public static OauthCriConfig claimedIdentityConfig = null;
    private static final List<SignedJWT> PARSED_CREDENTIALS = new ArrayList<>();
    private static final List<SignedJWT> PARSED_CREDENTIALS_WITH_INHERITED_IDENTITY =
            new ArrayList<>();
    private static final List<Gpg45Profile> ACCEPTED_PROFILES = List.of(M1A, M1B, M2B);
    private static final JourneyResponse JOURNEY_MET = new JourneyResponse("/journey/met");
    private static final JourneyResponse JOURNEY_UNMET = new JourneyResponse("/journey/unmet");
    private static final String JOURNEY_VCS_NOT_CORRELATED = "/journey/vcs-not-correlated";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static final ObjectMapper mapper = new ObjectMapper();

    static {
        try {
            addressConfig =
                    OauthCriConfig.builder()
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
                    OauthCriConfig.builder()
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
    @Mock private ConfigService configService;
    @Mock private UserIdentityService userIdentityService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @Mock private AuditService auditService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
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

        PARSED_CREDENTIALS_WITH_INHERITED_IDENTITY.addAll(PARSED_CREDENTIALS);
        PARSED_CREDENTIALS_WITH_INHERITED_IDENTITY.add(
                SignedJWT.parse(VC_INHERITED_IDENTITY_MIGRATION_WITH_NO_EVIDENCE));
    }

    @BeforeEach
    void setUpEach() {
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setIpvSessionId(TEST_SESSION_ID);

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
    void shouldReturnJourneyMetIfScoresSatisfyM1AGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVCsCorrelated(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());
        verify(mockVerifiableCredentialService).getVcStoreItems(TEST_USER_ID);
        verify(userIdentityService).getIdentityCredentials(any());

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(Vot.P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(Vot.P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyMetIfScoresSatisfyM1BGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getIdentityCredentials(any())).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(gpg45ProfileEvaluator.buildScore(any())).thenReturn(new Gpg45Scores(1, 1, 1, 1, 1));
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVCsCorrelated(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());
        verify(mockVerifiableCredentialService).getVcStoreItems(TEST_USER_ID);
        verify(userIdentityService).getIdentityCredentials(any());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(Vot.P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(Vot.P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyUnmetIfScoresDoNotSatisfyM1AGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getIdentityCredentials(any())).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 0));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVCsCorrelated(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_UNMET.getJourney(), response.getJourney());
        verify(mockVerifiableCredentialService).getVcStoreItems(TEST_USER_ID);
        verify(userIdentityService).getIdentityCredentials(any());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyUnmetIfGpg45ProfileNotMatched()
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getIdentityCredentials(any())).thenReturn(CREDENTIALS);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVCsCorrelated(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_UNMET.getJourney(), response.getJourney());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldRemoveOperationalProfileIfGpg45ProfileMatched() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockVerifiableCredentialService.getVcStoreItems(TEST_USER_ID))
                .thenReturn(VC_STORE_ITEMS);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVCsCorrelated(any())).thenReturn(true);
        when(configService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)).thenReturn(true);
        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        verify(mockVerifiableCredentialService).deleteVcStoreItem(TEST_USER_ID, HMRC_MIGRATION_CRI);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());
    }

    @Test
    void shouldNotRemoveOperationalProfileIfGpg45ProfileNotMatched() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getIdentityCredentials(any())).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.parseCredentials(any()))
                .thenReturn(PARSED_CREDENTIALS_WITH_INHERITED_IDENTITY);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.empty());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVCsCorrelated(any())).thenReturn(true);
        when(configService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)).thenReturn(true);
        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        verify(mockVerifiableCredentialService, never())
                .deleteVcStoreItem(TEST_USER_ID, HMRC_MIGRATION_CRI);

        assertEquals(JOURNEY_UNMET.getJourney(), response.getJourney());
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
        when(userIdentityService.areVCsCorrelated(any())).thenReturn(true);
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
        verify(mockVerifiableCredentialService).getVcStoreItems(TEST_USER_ID);
        verify(userIdentityService).getIdentityCredentials(any());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfCredentialOfUnknownType() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.areVCsCorrelated(any())).thenReturn(true);
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
        verify(mockVerifiableCredentialService).getVcStoreItems(TEST_USER_ID);
        verify(userIdentityService).getIdentityCredentials(any());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldSendAuditEventWhenProfileMatched() throws Exception {
        List<SignedJWT> parsedM1ACreds =
                List.of(
                        SignedJWT.parse(M1A_PASSPORT_VC),
                        SignedJWT.parse(M1A_ADDRESS_VC),
                        SignedJWT.parse(M1A_EXPERIAN_FRAUD_VC),
                        SignedJWT.parse(M1A_VERIFICATION_VC));
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(parsedM1ACreds);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.areVCsCorrelated(any())).thenReturn(true);
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
                List.of("6e61e5db-a175-4e16-af83-1ddfc5668e2b", "RB000103490087", "abc1234"),
                extension.getVcTxnIds());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(Vot.P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(Vot.P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnVcsNotCorrelatedIfFailedDueToNameCorrelationIssues() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVCsCorrelated(any())).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_VCS_NOT_CORRELATED, response.getJourney());

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(userIdentityService, times(1)).areVCsCorrelated(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfCredentialParseExceptionFromAreVcsCorrelated() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVCsCorrelated(any()))
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
    void shouldReturnJourneyUnmetIfCheckRequiresAdditionalEvidenceResponseTrue() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVCsCorrelated(any())).thenReturn(true);

        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_UNMET.getJourney(), response.getJourney());
        verify(mockVerifiableCredentialService).getVcStoreItems(TEST_USER_ID);
        verify(userIdentityService).getIdentityCredentials(any());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        verify(userIdentityService, times(1)).checkRequiresAdditionalEvidence(any());
    }

    @Test
    void shouldReturnJourneyMetIfCheckRequiresAdditionalEvidenceResponseFalse() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVCsCorrelated(any())).thenReturn(true);

        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());
        verify(mockVerifiableCredentialService).getVcStoreItems(TEST_USER_ID);
        verify(userIdentityService).getIdentityCredentials(any());

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(Vot.P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(Vot.P2, ipvSessionItem.getVot());
        verify(userIdentityService, times(1)).checkRequiresAdditionalEvidence(any());
    }

    private <T> T toResponseClass(Map<String, Object> handlerOutput, Class<T> responseClass) {
        return mapper.convertValue(handlerOutput, responseClass);
    }
}
