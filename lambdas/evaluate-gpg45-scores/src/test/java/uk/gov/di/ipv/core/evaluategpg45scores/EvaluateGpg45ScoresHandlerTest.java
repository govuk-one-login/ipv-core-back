package uk.gov.di.ipv.core.evaluategpg45scores;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
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
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigration;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL250NoEvidence;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcVerificationM1a;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.L1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M2B;

@ExtendWith(MockitoExtension.class)
class EvaluateGpg45ScoresHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static JourneyRequest request;
    private static List<VerifiableCredential> VCS_IN_STORE;
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";
    private static final List<Gpg45Profile> P2_PROFILES = List.of(M1A, M1B, M2B);
    private static final List<Gpg45Profile> P1_PROFILES = List.of(L1A);
    private static final List<Gpg45Profile> P1_AND_P2_PROFILES = List.of(M1A, M1B, M2B, L1A);
    private static final JourneyResponse JOURNEY_MET = new JourneyResponse("/journey/met");
    private static final JourneyResponse JOURNEY_UNMET = new JourneyResponse("/journey/unmet");
    private static final JourneyResponse JOURNEY_ERROR = new JourneyResponse("/journey/error");
    private static final String JOURNEY_VCS_NOT_CORRELATED = "/journey/vcs-not-correlated";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock private Context context;
    @Mock private ConfigService configService;
    @Mock private UserIdentityService userIdentityService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @Mock private AuditService auditService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private VerifiableCredentialService verifiableCredentialService;
    @Mock private SessionCredentialsService sessionCredentialsService;
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
        VCS_IN_STORE =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        M1A_ADDRESS_VC,
                        M1A_EXPERIAN_FRAUD_VC,
                        vcVerificationM1a(),
                        M1B_DCMAW_VC,
                        vcHmrcMigration());
    }

    @BeforeEach
    void setUpEach() {
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setIpvSessionId(TEST_SESSION_ID);

        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .state("test-state")
                        .vtr(List.of("P2"))
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
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());

        verify(sessionCredentialsService).getCredentials(TEST_SESSION_ID, TEST_USER_ID);
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
        when(gpg45ProfileEvaluator.buildScore(any())).thenReturn(new Gpg45Scores(1, 1, 1, 1, 1));
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());
        verify(sessionCredentialsService).getCredentials(TEST_SESSION_ID, TEST_USER_ID);
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
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 0));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_UNMET.getJourney(), response.getJourney());
        verify(sessionCredentialsService).getCredentials(TEST_SESSION_ID, TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyUnmetIfGpg45ProfileNotMatched()
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

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
        when(sessionCredentialsService.getCredentials(TEST_SESSION_ID, TEST_USER_ID))
                .thenReturn(VCS_IN_STORE);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(configService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)).thenReturn(true);
        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        verify(verifiableCredentialService).deleteHmrcInheritedIdentityIfPresent(VCS_IN_STORE);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());
    }

    @Test
    void shouldNotRemoveOperationalProfileIfGpg45ProfileNotMatched() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(sessionCredentialsService.getCredentials(TEST_SESSION_ID, TEST_USER_ID))
                .thenReturn(List.of(vcHmrcMigrationPCL250NoEvidence()));
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.empty());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(configService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)).thenReturn(true);
        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        verify(verifiableCredentialService, never()).deleteHmrcInheritedIdentityIfPresent(any());

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
    void shouldReturn500IfCredentialOfUnknownType() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
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
        verify(sessionCredentialsService).getCredentials(TEST_SESSION_ID, TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyErrorIfCantReadSessionCredentials() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(sessionCredentialsService.getCredentials(TEST_SESSION_ID, TEST_USER_ID))
                .thenThrow(
                        new VerifiableCredentialException(
                                SC_SERVER_ERROR, FAILED_TO_PARSE_ISSUED_CREDENTIALS));

        JourneyErrorResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyErrorResponse.class);

        assertEquals(JOURNEY_ERROR.getJourney(), response.getJourney());
        assertEquals(FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(), response.getMessage());
    }

    @Test
    void shouldSendAuditEventWhenProfileMatched() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(sessionCredentialsService.getCredentials(TEST_SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                                M1A_ADDRESS_VC,
                                M1A_EXPERIAN_FRAUD_VC,
                                vcVerificationM1a()));
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
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
                List.of("1c04edf0-a205-4585-8877-be6bd1776a39", "RB000103490087", "abc1234"),
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
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_VCS_NOT_CORRELATED, response.getJourney());

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(userIdentityService, times(1)).areVcsCorrelated(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfCredentialParseExceptionFromAreVcsCorrelated() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any()))
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
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_UNMET.getJourney(), response.getJourney());
        verify(sessionCredentialsService).getCredentials(TEST_SESSION_ID, TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        verify(userIdentityService, times(1)).checkRequiresAdditionalEvidence(any());
    }

    @Test
    void shouldReturnJourneyMetIfCheckRequiresAdditionalEvidenceResponseFalse() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());
        verify(sessionCredentialsService).getCredentials(TEST_SESSION_ID, TEST_USER_ID);

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(Vot.P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(Vot.P2, ipvSessionItem.getVot());
        verify(userIdentityService, times(1)).checkRequiresAdditionalEvidence(any());
    }

    @Test
    void shouldReturnJourneyMetForLowConfidence() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P1_PROFILES)))
                .thenReturn(Optional.of(L1A));
        clientOAuthSessionItem.setVtr(List.of("P1"));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());

        assertEquals(Vot.P1, ipvSessionItem.getVot());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService).sendAuditEvent(auditEventCaptor.capture());
        AuditEvent auditEvent = auditEventCaptor.getValue();
        AuditExtensionGpg45ProfileMatched extension =
                (AuditExtensionGpg45ProfileMatched) auditEvent.getExtensions();
        assertEquals(L1A, extension.getGpg45Profile());
    }

    @Test
    void shouldReturnJourneyMetForMeetingMediumAndLowConfidences() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        clientOAuthSessionItem.setVtr(List.of("P1", "P2"));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P1_AND_P2_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());
        verify(ipvSessionItem).setVot(Vot.P2);
    }

    @ParameterizedTest
    @MethodSource("vtrsAndExpectedGpg45Profiles")
    void shouldUseCorrectGpg45ProfilesFromVtrToCheckMatchingVcs(
            List<String> vtr, List<Gpg45Profile> profiles)
            throws SqsException, UnknownEvidenceTypeException, CredentialParseException {
        // Arrange
        clientOAuthSessionItem.setVtr(vtr);

        // Act
        evaluateGpg45ScoresHandler.hasMatchingGpg45Profile(
                List.of(), ipvSessionItem, clientOAuthSessionItem, TEST_CLIENT_SOURCE_IP, null);

        // Assert
        verify(gpg45ProfileEvaluator).getFirstMatchingProfile(null, profiles);
    }

    private static Stream<Arguments> vtrsAndExpectedGpg45Profiles() {
        return Stream.of(
                Arguments.of(List.of("P1"), P1_PROFILES),
                Arguments.of(List.of("P2"), P2_PROFILES),
                Arguments.of(List.of("P1", "P2"), P1_AND_P2_PROFILES),
                Arguments.of(List.of("P2", "P1"), P1_AND_P2_PROFILES));
    }

    private <T> T toResponseClass(Map<String, Object> handlerOutput, Class<T> responseClass) {
        return OBJECT_MAPPER.convertValue(handlerOutput, responseClass);
    }
}
