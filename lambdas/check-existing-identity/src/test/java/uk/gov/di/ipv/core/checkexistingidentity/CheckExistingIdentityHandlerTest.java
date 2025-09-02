package uk.gov.di.ipv.core.checkexistingidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.ais.service.AisService;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionAccountIntervention;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionPreviousAchievedVot;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionPreviousIpvSessionId;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.cricheckingservice.CriCheckingService;
import uk.gov.di.ipv.core.library.criresponse.domain.AsyncCriStatus;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.AisInterventionType;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.MissingSecurityCheckCredential;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.journeys.JourneyUris;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.ConfigServiceHelper;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatcher;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.model.ContraIndicator;
import uk.gov.di.model.Mitigation;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.AIS_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.P1_JOURNEYS_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.REPEAT_FRAUD_CHECK;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.RESET_IDENTITY;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.SIS_VERIFICATION;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.STORED_IDENTITY_SERVICE;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_ACCOUNT_BLOCKED;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_ACCOUNT_SUSPENDED;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_FORCED_USER_PASSWORD_RESET;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawAsyncDrivingPermitDva;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawAsyncDrivingPermitDvaFailedChecks;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawDrivingPermitDvaM1b;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudM1aExpired;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianKbvM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fPassportPhotoM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitDvaValid;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;
import static uk.gov.di.ipv.core.library.journeys.Events.ENHANCED_VERIFICATION_EVENT;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ACCOUNT_INTERVENTION_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_F2F_PENDING_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_NO_CI_MEDIUM_CONFIDENCE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_NO_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IPV_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IPV_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REPEAT_FRAUD_CHECK_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REUSE_WITH_STORE_PATH;

@ExtendWith(MockitoExtension.class)
class CheckExistingIdentityHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";
    private static final String TEST_FEATURE_SET = "test-feature-set";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static final String TEST_JOURNEY = "journey/check-existing-identity";
    private static final String JOURNEY_ERROR_PATH = "/journey/error";
    public static final String EVCS_TEST_TOKEN = "evcsTestToken";
    public static final String TEST_CRI_OAUTH_SESSION_ID = "test-cri-oauth-session-id";
    public static final String TEST_PREVIOUS_IPV_SESSION_ID = "previous-ipv-session-id";
    private static final List<VerifiableCredential> VCS_FROM_STORE =
            List.of(
                    vcWebPassportSuccessful(),
                    vcAddressM1a(),
                    vcExperianFraudM1a(),
                    vcExperianKbvM1a(),
                    vcDcmawDrivingPermitDvaM1b());
    private static final JourneyResponse JOURNEY_REUSE = new JourneyResponse(JOURNEY_REUSE_PATH);
    private static final JourneyResponse JOURNEY_REUSE_WITH_STORE =
            new JourneyResponse(JOURNEY_REUSE_WITH_STORE_PATH);
    private static final JourneyResponse JOURNEY_IPV_GPG45_LOW =
            new JourneyResponse(JOURNEY_IPV_GPG45_LOW_PATH);
    private static final JourneyResponse JOURNEY_IPV_GPG45_MEDIUM =
            new JourneyResponse(JOURNEY_IPV_GPG45_MEDIUM_PATH);
    private static final JourneyResponse JOURNEY_PENDING =
            new JourneyResponse(JOURNEY_F2F_PENDING_PATH);
    private static final JourneyResponse JOURNEY_F2F_FAIL =
            new JourneyResponse(JOURNEY_F2F_FAIL_PATH);
    private static final JourneyResponse JOURNEY_REPEAT_FRAUD_CHECK =
            new JourneyResponse(JOURNEY_REPEAT_FRAUD_CHECK_PATH);
    private static final JourneyResponse JOURNEY_FAIL_WITH_NO_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_NO_CI_PATH);
    private static final JourneyResponse JOURNEY_FAIL_WITH_NO_CI_MEDIUM_CONFIDENCE =
            new JourneyResponse(JOURNEY_FAIL_WITH_NO_CI_MEDIUM_CONFIDENCE_PATH);
    private static final JourneyResponse JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW =
            new JourneyResponse(JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW_PATH);
    private static final JourneyResponse JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM =
            new JourneyResponse(JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM_PATH);
    private static final JourneyResponse JOURNEY_ACCOUNT_INTERVENTION =
            new JourneyResponse(JOURNEY_ACCOUNT_INTERVENTION_PATH);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final VerifiableCredential gpg45Vc = vcWebDrivingPermitDvaValid();
    private static final VerifiableCredential f2fVc = vcF2fPassportPhotoM1a();
    private static AsyncCriStatus emptyAsyncCriStatus =
            new AsyncCriStatus(null, null, false, false, false);

    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private CriCheckingService criCheckingService;
    @Mock private CriResponseService criResponseService;
    @Mock private CriOAuthSessionService criOAuthSessionService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private ConfigService configService;
    @Mock private Config mockConfig;
    @Mock private AuditService auditService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private CimitService cimitService;
    @Mock private CimitUtilityService cimitUtilityService;
    @Mock private EvcsService mockEvcsService;
    @Mock private SessionCredentialsService mockSessionCredentialService;
    @Mock private AisService mockAisService;
    @Mock private VotMatcher mockVotMatcher;
    @InjectMocks private CheckExistingIdentityHandler checkExistingIdentityHandler;

    @Spy private IpvSessionItem ipvSessionItem;
    @Captor private ArgumentCaptor<AuditEvent> auditEventArgumentCaptor;
    private JourneyRequest event;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeEach
    void setUpEach() {
        event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_CLIENT_SOURCE_IP)
                        .clientOAuthSessionId(TEST_CLIENT_SOURCE_IP)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .build();

        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setIpvSessionId(TEST_SESSION_ID);
        ipvSessionItem.setVot(Vot.P0);

        lenient()
                .when(mockVotMatcher.findStrongestMatches(any(), any(), any(), anyBoolean()))
                .thenReturn(new VotMatchingResult(Optional.empty(), Optional.empty(), null));

        lenient().when(configService.enabled(SIS_VERIFICATION)).thenReturn(false);

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
                        .reproveIdentity(false)
                        .vtr(List.of(P2.name()))
                        .evcsAccessToken(EVCS_TEST_TOKEN)
                        .build();

        ConfigServiceHelper.stubDefaultComponentIdConfig(configService, mockConfig);
    }

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(auditService);
        auditInOrder.verify(auditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

    @Nested
    class NewIdentityJourneys {
        @BeforeEach
        void setUp() throws Exception {
            when(configService.enabled(AIS_ENABLED)).thenReturn(false);
            when(configService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(true);
            when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID))
                    .thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
            when(configService.enabled(AIS_ENABLED)).thenReturn(false);
        }

        @Test
        void shouldReturnJourneyNewGpg45MediumIdentityForP2Vtr() throws Exception {
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

            verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
            verify(mockEvcsService, times(1)).invalidateStoredIdentityRecord(TEST_USER_ID);
        }

        @Test
        void shouldReturnJourneyNewGpg45LowIdentityForP1Vtr() throws Exception {
            clientOAuthSessionItem.setVtr(List.of(P2.name(), P1.name()));
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IPV_GPG45_LOW, journeyResponse);

            verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
        }

        @Test
        void shouldReturnF2FFailForF2FCompleteAndVCsDoNotCorrelate() throws Exception {
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(
                            Map.of(
                                    PENDING_RETURN,
                                    new ArrayList<>(List.of(vcF2fPassportPhotoM1a()))));
            when(criResponseService.getCriResponseItems(TEST_USER_ID))
                    .thenReturn(
                            List.of(
                                    CriResponseItem.builder()
                                            .credentialIssuer(F2F.getId())
                                            .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                            .build()));
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_PENDING, false, true, false));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(false);

            clientOAuthSessionItem.setVtr(List.of(P2.name()));

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

            verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(
                    AuditEventTypes.IPV_F2F_CORRELATION_FAIL,
                    auditEventArgumentCaptor.getAllValues().get(0).getEventName());
            verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @ParameterizedTest
        @MethodSource("lowAndMediumConfidenceVtrs")
        void shouldReturnJourneyDcmawAsyncVcReceivedForDcmawAsyncComplete(
                List<String> vtr, JourneyResponse expectedJourney)
                throws IpvSessionNotFoundException,
                        HttpResponseExceptionWithErrorBody,
                        CredentialParseException,
                        VerifiableCredentialException,
                        EvcsServiceException {
            // Arrange
            when(criResponseService.getCriResponseItem(TEST_USER_ID, DCMAW_ASYNC))
                    .thenReturn(
                            CriResponseItem.builder()
                                    .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                    .build());
            when(criResponseService.getCriResponseItems(TEST_USER_ID))
                    .thenReturn(
                            List.of(
                                    CriResponseItem.builder()
                                            .credentialIssuer(DCMAW_ASYNC.getId())
                                            .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                            .build()));
            when(criOAuthSessionService.getCriOauthSessionItem(TEST_CRI_OAUTH_SESSION_ID))
                    .thenReturn(
                            CriOAuthSessionItem.builder()
                                    .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                                    .build());
            var previousIpvSession = new IpvSessionItem();
            previousIpvSession.setIpvSessionId(TEST_PREVIOUS_IPV_SESSION_ID);
            when(ipvSessionService.getIpvSessionByClientOAuthSessionId(
                            TEST_CLIENT_OAUTH_SESSION_ID))
                    .thenReturn(previousIpvSession);
            var vcs = List.of(vcDcmawAsyncDrivingPermitDva());
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                    .thenReturn(
                            new AsyncCriStatus(
                                    DCMAW_ASYNC,
                                    AsyncCriStatus.STATUS_PENDING,
                                    false,
                                    true,
                                    false));
            Mockito.lenient().when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(true);
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(PENDING_RETURN, vcs));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

            clientOAuthSessionItem.setVtr(vtr);

            // Act
            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            // Assert
            assertEquals(expectedJourney, journeyResponse);
            verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
            verify(mockSessionCredentialService).persistCredentials(vcs, TEST_SESSION_ID, true);
            verify(auditService).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(
                    AuditEventTypes.IPV_APP_SESSION_RECOVERED,
                    auditEventArgumentCaptor.getValue().getEventName());
            assertEquals(
                    TEST_PREVIOUS_IPV_SESSION_ID,
                    ((AuditExtensionPreviousIpvSessionId)
                                    auditEventArgumentCaptor.getValue().getExtensions())
                            .getPreviousIpvSessionId());
            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        static Stream<Arguments> lowAndMediumConfidenceVtrs() {
            return Stream.of(
                    Arguments.of(
                            List.of(Vot.P1.name(), Vot.P2.name()),
                            JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW),
                    Arguments.of(List.of(Vot.P2.name()), JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM));
        }

        @Test
        void shouldReturnJourneyIpvGpg45MediumForDcmawAsyncCompleteAndVcIsExpired()
                throws HttpResponseExceptionWithErrorBody,
                        CredentialParseException,
                        EvcsServiceException {
            // Arrange
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(PENDING_RETURN, List.of(vcDcmawAsyncDrivingPermitDva())));
            when(criResponseService.getCriResponseItems(TEST_USER_ID))
                    .thenReturn(
                            List.of(
                                    CriResponseItem.builder()
                                            .credentialIssuer(DCMAW_ASYNC.getId())
                                            .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                            .build()));
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                    .thenReturn(emptyAsyncCriStatus);
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

            // Act
            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            // Assert
            assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

            verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnJourneyFailForUnsuccessfulDcmawAsync()
                throws IpvSessionNotFoundException,
                        HttpResponseExceptionWithErrorBody,
                        CredentialParseException,
                        VerifiableCredentialException,
                        EvcsServiceException,
                        CiExtractionException,
                        ConfigException,
                        CiRetrievalException,
                        MissingSecurityCheckCredential {
            // Arrange
            when(criResponseService.getCriResponseItem(TEST_USER_ID, DCMAW_ASYNC))
                    .thenReturn(
                            CriResponseItem.builder()
                                    .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                    .build());
            when(criResponseService.getCriResponseItems(TEST_USER_ID))
                    .thenReturn(
                            List.of(
                                    CriResponseItem.builder()
                                            .credentialIssuer(DCMAW_ASYNC.getId())
                                            .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                            .build()));
            when(criOAuthSessionService.getCriOauthSessionItem(TEST_CRI_OAUTH_SESSION_ID))
                    .thenReturn(
                            CriOAuthSessionItem.builder()
                                    .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                                    .build());
            var previousIpvSession = new IpvSessionItem();
            previousIpvSession.setIpvSessionId(TEST_PREVIOUS_IPV_SESSION_ID);
            when(ipvSessionService.getIpvSessionByClientOAuthSessionId(
                            TEST_CLIENT_OAUTH_SESSION_ID))
                    .thenReturn(previousIpvSession);
            var vcs = List.of(vcDcmawAsyncDrivingPermitDvaFailedChecks());
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                    .thenReturn(
                            new AsyncCriStatus(
                                    DCMAW_ASYNC,
                                    AsyncCriStatus.STATUS_PENDING,
                                    false,
                                    true,
                                    false));
            Mockito.lenient().when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(true);
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(PENDING_RETURN, vcs));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
            clientOAuthSessionItem.setVtr(List.of(Vot.P2.name()));
            when(criCheckingService.checkVcResponse(
                            vcs,
                            TEST_CLIENT_SOURCE_IP,
                            clientOAuthSessionItem,
                            ipvSessionItem,
                            vcs))
                    .thenReturn(JOURNEY_FAIL_WITH_NO_CI);

            // Act
            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            // Assert
            assertEquals(JOURNEY_FAIL_WITH_NO_CI_MEDIUM_CONFIDENCE, journeyResponse);
            verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
            verify(mockSessionCredentialService).persistCredentials(vcs, TEST_SESSION_ID, true);
            verify(auditService).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(
                    AuditEventTypes.IPV_APP_SESSION_RECOVERED,
                    auditEventArgumentCaptor.getValue().getEventName());
            assertEquals(
                    TEST_PREVIOUS_IPV_SESSION_ID,
                    ((AuditExtensionPreviousIpvSessionId)
                                    auditEventArgumentCaptor.getValue().getExtensions())
                            .getPreviousIpvSessionId());
            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnNoMatchResponseIfVCsDoNotCorrelate() throws Exception {
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(vcF2fPassportPhotoM1a())));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(false);
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);

            clientOAuthSessionItem.setVtr(List.of(P2.name()));

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

            verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnJourneyIpvGpg45MediumResponseIfNoProfileAttainsVot() throws Exception {
            var credentials = new ArrayList<VerifiableCredential>();
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, credentials));
            clientOAuthSessionItem.setVtr(List.of("P2"));
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnJourneyIpvGpg45MediumResponseIfScoresDoNotSatisfyP2Gpg45Profile()
                throws Exception {
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, VCS_FROM_STORE));
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

            verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldNotSendAuditEventIfNewUser() throws Exception {
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of());

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IPV_GPG45_MEDIUM_PATH, journeyResponse.getJourney());

            verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
            verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnPendingResponseIfFaceToFaceVerificationIsPending() {
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_PENDING, true, false, false));

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_PENDING, journeyResponse);

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnPendingResponseIfFaceToFaceVerificationIsPendingAndBreachingCi()
                throws Exception {
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_PENDING, true, false, false));
            when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(true);
            when(cimitUtilityService.getCiMitigationEvent(any(), any()))
                    .thenReturn(Optional.of(ENHANCED_VERIFICATION_EVENT));

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_PENDING, journeyResponse);

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnFailResponseIfFaceToFaceVerificationIsError() {
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_ERROR, true, false, false));

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnFailResponseIfFaceToFaceVerificationIsAbandon() {
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_ABANDON, true, false, false));

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnFailResponseForFaceToFaceVerificationIfNoMatchedProfile()
                throws Exception {
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(
                            Map.of(
                                    PENDING_RETURN,
                                    new ArrayList<>(List.of(vcF2fPassportPhotoM1a()))));
            when(criResponseService.getCriResponseItems(TEST_USER_ID))
                    .thenReturn(
                            List.of(
                                    CriResponseItem.builder()
                                            .credentialIssuer(F2F.getId())
                                            .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                            .build()));
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_PENDING, false, true, false));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(
                    AuditEventTypes.IPV_F2F_PROFILE_NOT_MET_FAIL,
                    auditEventArgumentCaptor.getAllValues().get(0).getEventName());

            assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnFailResponseForFaceToFaceIfVCsDoNotCorrelate() throws Exception {
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(
                            Map.of(
                                    PENDING_RETURN,
                                    new ArrayList<>(List.of(vcF2fPassportPhotoM1a()))));
            when(criResponseService.getCriResponseItems(TEST_USER_ID))
                    .thenReturn(
                            List.of(
                                    CriResponseItem.builder()
                                            .credentialIssuer(F2F.getId())
                                            .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                            .build()));
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_PENDING, false, true, false));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(false);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(
                    AuditEventTypes.IPV_F2F_CORRELATION_FAIL,
                    auditEventArgumentCaptor.getAllValues().get(0).getEventName());
            assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnJourneyIpvGpg45MediumIfDataDoesNotCorrelateAndNotF2F() throws Exception {
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(
                            Map.of(
                                    PENDING_RETURN,
                                    new ArrayList<>(List.of(vcF2fPassportPhotoM1a()))));
            when(criResponseService.getCriResponseItems(TEST_USER_ID))
                    .thenReturn(
                            List.of(
                                    CriResponseItem.builder()
                                            .credentialIssuer(F2F.getId())
                                            .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                            .build()));
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                    .thenReturn(emptyAsyncCriStatus);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnFailWithCiJourneyResponseForCiBreachAndNoMitigationsAvailable()
                throws Exception {
            when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(List.of());
            when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(true);
            when(cimitUtilityService.getCiMitigationEvent(any(), any()))
                    .thenReturn(Optional.empty());
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);

            var response =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_FAIL_WITH_CI_PATH, response.getJourney());
        }

        @Test
        void shouldReturnNewIdentityJourneyWhenCiIsBreachingButMitigationIsAvailable()
                throws Exception {
            when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(List.of());
            when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(true);
            when(cimitUtilityService.getCiMitigationEvent(any(), any()))
                    .thenReturn(Optional.of(ENHANCED_VERIFICATION_EVENT));
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);

            var response =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IPV_GPG45_MEDIUM_PATH, response.getJourney());
        }

        private static Stream<Arguments> f2fIncompleteStatus() {
            return Stream.of(
                    Arguments.of(AsyncCriStatus.STATUS_PENDING, JOURNEY_F2F_PENDING_PATH),
                    Arguments.of(AsyncCriStatus.STATUS_ABANDON, JOURNEY_F2F_FAIL_PATH),
                    Arguments.of(AsyncCriStatus.STATUS_ERROR, JOURNEY_F2F_FAIL_PATH));
        }

        @ParameterizedTest
        @MethodSource("f2fIncompleteStatus")
        void shouldReturnF2fJourneyResponseWhenCiIsBreachingButMitigationIsAvailable(
                String asyncCriStatus, String expectedJourney) throws Exception {
            when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(List.of());
            when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(true);
            when(cimitUtilityService.getCiMitigationEvent(any(), any()))
                    .thenReturn(Optional.of(ENHANCED_VERIFICATION_EVENT));
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, List.of(), false))
                    .thenReturn(new AsyncCriStatus(F2F, asyncCriStatus, true, true, false));

            var response =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(expectedJourney, response.getJourney());
        }

        @Test
        void shouldReturnNewIdentityJourneyIfNotBreachingCiThreshold() throws Exception {
            var mitigatedCI = new ContraIndicator();
            mitigatedCI.setCode("test_code");
            mitigatedCI.setMitigation(List.of(new Mitigation()));
            var testContraIndicators = List.of(mitigatedCI);

            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of());
            when(cimitUtilityService.getContraIndicatorsFromVc(any()))
                    .thenReturn(testContraIndicators);
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);
            when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(false);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IPV_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
        }

        @Test
        void shouldReturnF2fFailJourneyResponseWhenFailedToMatchF2fProfile() throws Exception {
            var mitigatedCI = new ContraIndicator();
            mitigatedCI.setCode("test_code");
            mitigatedCI.setMitigation(List.of(new Mitigation()));
            var testContraIndicators = List.of(mitigatedCI);

            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(
                            Map.of(
                                    PENDING_RETURN,
                                    new ArrayList<>(List.of(vcF2fPassportPhotoM1a()))));
            when(criResponseService.getCriResponseItems(TEST_USER_ID))
                    .thenReturn(
                            List.of(
                                    CriResponseItem.builder()
                                            .credentialIssuer(F2F.getId())
                                            .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                            .build()));
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_PENDING, false, true, false));
            when(cimitUtilityService.getContraIndicatorsFromVc(any()))
                    .thenReturn(testContraIndicators);
            when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(false);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_F2F_FAIL_PATH, journeyResponse.getJourney());
        }

        @Test
        void shouldReturnNewIdentityJourneyWhenPendingReturnVcNotAssociatedWithPendingRecord()
                throws Exception {
            // Arrange
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(PENDING_RETURN, new ArrayList<>(List.of(f2fVc))));
            when(criResponseService.getCriResponseItems(TEST_USER_ID)).thenReturn(List.of());
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, List.of(), false))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_PENDING, false, false, false));
            when(cimitUtilityService.isBreachingCiThreshold(List.of(), P2)).thenReturn(false);

            // Act
            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            // Assert
            assertEquals(JOURNEY_IPV_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
        }
    }

    @Nested
    @DisplayName("reuse journeys")
    class ReuseJourneys {
        @BeforeEach
        void reuseSetup() throws Exception {
            when(configService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(false);
            when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID))
                    .thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
            when(configService.enabled(AIS_ENABLED)).thenReturn(false);
        }

        @Test
        void shouldUseEvcsService() throws Exception {
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc)));

            checkExistingIdentityHandler.handleRequest(event, context);

            verify(clientOAuthSessionDetailsService).getClientOAuthSession(any());
            verify(mockEvcsService)
                    .fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN);
        }

        @ParameterizedTest
        @EnumSource(names = {"M1A", "M1B", "M2B"})
        void shouldReturnJourneyReuseResponseIfScoresSatisfyGpg45Profile(
                Gpg45Profile matchedProfile) throws Exception {
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc)));
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);
            when(mockVotMatcher.findStrongestMatches(
                            List.of(P2), List.of(gpg45Vc), List.of(), true))
                    .thenReturn(buildMatchResultFor(P2, matchedProfile));
            when(mockVotMatcher.findStrongestMatches(
                            Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                            List.of(gpg45Vc),
                            List.of(),
                            true))
                    .thenReturn(buildMatchResultFor(P2, matchedProfile));
            when(configService.enabled(RESET_IDENTITY)).thenReturn(false);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REUSE, journeyResponse);

            verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(
                    AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                    auditEventArgumentCaptor.getAllValues().get(0).getEventName());

            var ext =
                    (AuditExtensionPreviousAchievedVot)
                            auditEventArgumentCaptor.getAllValues().get(0).getExtensions();
            assertEquals(P2, ext.getPreviousAchievedVot());

            verify(mockSessionCredentialService)
                    .persistCredentials(List.of(gpg45Vc), ipvSessionItem.getIpvSessionId(), false);

            var inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(P2);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(P2, ipvSessionItem.getVot());
        }

        @Test
        void shouldEmitReuseCompleteWithNullPreviousAchievedVotWhenComputationFails()
                throws Exception {
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc)));
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);
            when(mockVotMatcher.findStrongestMatches(
                            List.of(P2), List.of(gpg45Vc), List.of(), true))
                    .thenReturn(buildMatchResultFor(P2, M1A));
            when(mockVotMatcher.findStrongestMatches(
                            Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                            List.of(gpg45Vc),
                            List.of(),
                            true))
                    .thenThrow(new RuntimeException("boom"));

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REUSE, journeyResponse);
            verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(
                    AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                    auditEventArgumentCaptor.getAllValues().get(0).getEventName());
            var ext =
                    (AuditExtensionPreviousAchievedVot)
                            auditEventArgumentCaptor.getAllValues().get(0).getExtensions();
            assertEquals(null, ext.getPreviousAchievedVot());
        }

        @Test
        void shouldReturnJourneyReuseWithStoreResponseIfIsF2fPendingReturn() throws Exception {
            var vcs = List.of(gpg45Vc, vcF2fPassportPhotoM1a());
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(PENDING_RETURN, vcs));
            when(criResponseService.getCriResponseItems(TEST_USER_ID))
                    .thenReturn(
                            List.of(
                                    CriResponseItem.builder()
                                            .credentialIssuer(F2F.getId())
                                            .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                            .build()));
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, vcs, true))
                    .thenReturn(emptyAsyncCriStatus);
            when(mockVotMatcher.findStrongestMatches(List.of(P2), vcs, List.of(), true))
                    .thenReturn(buildMatchResultFor(P2, M1A));
            when(mockVotMatcher.findStrongestMatches(
                            Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH, vcs, List.of(), true))
                    .thenReturn(buildMatchResultFor(P2, M1A));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REUSE_WITH_STORE, journeyResponse);
        }

        @Test
        void shouldReturnErrorResponseIfVcCanNotBeStoredInSessionCredentialTable()
                throws Exception {
            when(mockVotMatcher.findStrongestMatches(List.of(P2), List.of(), List.of(), true))
                    .thenReturn(buildMatchResultFor(P2, M1A));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
            doThrow(
                            new VerifiableCredentialException(
                                    HTTPResponse.SC_SERVER_ERROR,
                                    ErrorResponse.FAILED_TO_SAVE_CREDENTIAL))
                    .when(mockSessionCredentialService)
                    .persistCredentials(any(), any(), anyBoolean());

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyErrorResponse.class);

            assertEquals(JOURNEY_ERROR_PATH, journeyResponse.getJourney());

            assertEquals(HTTPResponse.SC_SERVER_ERROR, journeyResponse.getStatusCode());
            assertEquals(
                    ErrorResponse.FAILED_TO_SAVE_CREDENTIAL.getCode(), journeyResponse.getCode());
            assertEquals(
                    ErrorResponse.FAILED_TO_SAVE_CREDENTIAL.getMessage(),
                    journeyResponse.getMessage());
        }
    }

    @Test
    void shouldReturn400IfSessionIdNotInHeader() throws Exception {
        var eventWithoutHeaders = JourneyRequest.builder().build();

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(eventWithoutHeaders, context),
                        JourneyErrorResponse.class);

        assertEquals(JOURNEY_ERROR_PATH, journeyResponse.getJourney());

        assertEquals(HttpStatusCode.BAD_REQUEST, journeyResponse.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), journeyResponse.getCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), journeyResponse.getMessage());
        verify(clientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfFailedToRetrieveCisFromStorageSystem() throws Exception {
        when(configService.enabled(AIS_ENABLED)).thenReturn(false);
        when(configService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(true);
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(cimitService.fetchContraIndicatorsVc(anyString(), anyString(), anyString(), any()))
                .thenThrow(CiRetrievalException.class);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of());

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_STORED_CIS.getCode(), response.getCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_STORED_CIS.getMessage(), response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfFailedToGetCisFromCiVc() throws Exception {
        when(configService.enabled(AIS_ENABLED)).thenReturn(false);
        when(configService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(true);
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(cimitUtilityService.getContraIndicatorsFromVc(any()))
                .thenThrow(CiExtractionException.class);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of());

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_EXTRACT_CIS_FROM_VC.getCode(), response.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_EXTRACT_CIS_FROM_VC.getMessage(), response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfUnableToParseCredentials() throws Exception {
        when(configService.enabled(AIS_ENABLED)).thenReturn(false);
        when(configService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(true);
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                .thenThrow(CredentialParseException.class);

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getCode(),
                response.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getMessage(),
                response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfFailedToGetCimitConfig() throws Exception {
        when(configService.enabled(AIS_ENABLED)).thenReturn(false);
        when(configService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(true);
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(Boolean.TRUE);
        when(cimitUtilityService.getCiMitigationEvent(any(), any()))
                .thenThrow(new ConfigException("Failed to get cimit config"));

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE_CONFIG.getCode(), response.getCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE_CONFIG.getMessage(), response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfUnrecognisedCiReceived() throws Exception {
        when(configService.enabled(AIS_ENABLED)).thenReturn(false);
        when(configService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(true);
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(cimitService.fetchContraIndicatorsVc(
                        TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP, ipvSessionItem))
                .thenThrow(new UnrecognisedCiException("Unrecognised CI"));

        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(JourneyUris.JOURNEY_ERROR_PATH, response.getJourney());
        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.UNRECOGNISED_CI_CODE.getCode(), response.getCode());
        assertEquals(ErrorResponse.UNRECOGNISED_CI_CODE.getMessage(), response.getMessage());
    }

    @Nested
    class ReproveIdentity {
        @BeforeEach
        void beforeEach() throws Exception {
            when(configService.enabled(AIS_ENABLED)).thenReturn(false);
            when(configService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(true);
            when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID))
                    .thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldReturnReproveP2JourneyIfReproveIdentityFlagSet() {
            clientOAuthSessionItem.setReproveIdentity(Boolean.TRUE);
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, List.of(), false))
                    .thenReturn(emptyAsyncCriStatus);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
        }

        @Test
        void shouldReturnReproveP1JourneyIfReproveIdentityFlagSet() {
            clientOAuthSessionItem.setReproveIdentity(Boolean.TRUE);
            clientOAuthSessionItem.setVtr(List.of(P2.name(), P1.name()));
            lenient().when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(true);
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH, journeyResponse.getJourney());
        }

        @Test
        void shouldReturnReproveP2JourneyIfReproveIdentityFlagSetAndPendingF2FDoesNotHaveFlag() {
            clientOAuthSessionItem.setReproveIdentity(Boolean.TRUE);
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, List.of(), false))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_PENDING, false, false, false));

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
        }

        @Test
        void shouldReturnReproveP2JourneyIfReproveIdentityFlagSetAndIdentityIsNotPending()
                throws Exception {
            clientOAuthSessionItem.setReproveIdentity(Boolean.TRUE);
            var vcs = new ArrayList<>(List.of(gpg45Vc, f2fVc));
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, vcs));
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, vcs, false))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_PENDING, false, true, true));

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
        }

        @Test
        void shouldNotReturnReproveJourneyIfUserHasPendingF2FWithReproveFlag() throws Exception {
            clientOAuthSessionItem.setReproveIdentity(Boolean.TRUE);
            var vcs = new ArrayList<>(List.of(f2fVc));
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(PENDING_RETURN, vcs));
            when(criResponseService.getCriResponseItems(TEST_USER_ID))
                    .thenReturn(
                            List.of(
                                    CriResponseItem.builder()
                                            .credentialIssuer(F2F.getId())
                                            .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                            .build()));
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, vcs, true))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_PENDING, true, true, true));

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_F2F_PENDING_PATH, journeyResponse.getJourney());

            verify(criResponseService, never()).updateCriResponseItem(any());
        }

        @Test
        void shouldReturnReproveP2JourneyStepResponseIfResetIdentityTrue() throws Exception {
            when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(List.of());
            when(configService.enabled(RESET_IDENTITY)).thenReturn(true);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
        }

        @Test
        void shouldReturnReproveP1JourneyStepResponseIfResetIdentityTrueAndP1InVtr()
                throws Exception {
            clientOAuthSessionItem.setVtr(List.of(P2.name(), P1.name()));
            when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(List.of());
            when(configService.enabled(RESET_IDENTITY)).thenReturn(true);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH, journeyResponse.getJourney());
        }
    }

    @Nested
    class RepeatFraudCheck {
        @BeforeEach
        void setup() throws Exception {
            when(configService.enabled(AIS_ENABLED)).thenReturn(false);
            when(configService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(true);
            when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID))
                    .thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldReturnJourneyRepeatFraudCheckResponseIfExpiredFraudAndFlagIsTrue()
                throws Exception {
            var fraudVc = vcExperianFraudM1aExpired();
            var vcs =
                    List.of(
                            vcWebPassportSuccessful(),
                            vcAddressM1a(),
                            fraudVc,
                            vcExperianKbvM1a(),
                            vcDcmawDrivingPermitDvaM1b());
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, vcs));

            when(mockVotMatcher.findStrongestMatches(List.of(P2), vcs, List.of(), true))
                    .thenReturn(buildMatchResultFor(P2, M1B));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
            when(configService.enabled(RESET_IDENTITY)).thenReturn(false);
            when(configService.enabled(REPEAT_FRAUD_CHECK)).thenReturn(true);
            when(configService.getConfiguration().getSelf().getComponentId())
                    .thenReturn(URI.create("http://ipv/"));
            when(configService.getConfiguration().getSelf().getFraudCheckExpiryPeriodHours())
                    .thenReturn(1);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);
            assertEquals(JOURNEY_REPEAT_FRAUD_CHECK, journeyResponse);

            var expectedStoredVc = vcs.stream().filter(vc -> vc != fraudVc).toList();
            verify(mockSessionCredentialService)
                    .persistCredentials(expectedStoredVc, ipvSessionItem.getIpvSessionId(), false);

            assertEquals(Vot.P0, ipvSessionItem.getVot());
        }

        @Test
        void shouldNotReturnJourneyRepeatFraudCheckResponseIfNotExpiredFraudAndFlagIsTrue()
                throws Exception {
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, false, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, VCS_FROM_STORE));

            when(mockVotMatcher.findStrongestMatches(List.of(P2), VCS_FROM_STORE, List.of(), true))
                    .thenReturn(buildMatchResultFor(P2, M1B));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
            when(configService.enabled(RESET_IDENTITY)).thenReturn(false);
            when(configService.enabled(REPEAT_FRAUD_CHECK)).thenReturn(true);
            when(configService.getConfiguration().getSelf().getComponentId())
                    .thenReturn(URI.create("http://ipv/"));
            when(configService.getConfiguration().getSelf().getFraudCheckExpiryPeriodHours())
                    .thenReturn(100000000); // not the best way to test this

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);
            assertNotEquals(JOURNEY_REPEAT_FRAUD_CHECK, journeyResponse);

            verify(mockSessionCredentialService)
                    .persistCredentials(VCS_FROM_STORE, ipvSessionItem.getIpvSessionId(), false);

            var inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(P2);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(P2, ipvSessionItem.getVot());
        }
    }

    @Nested
    class JourneysWithAccountInterventionEnabled {
        @BeforeEach
        void setup() throws Exception {
            when(configService.enabled(AIS_ENABLED)).thenReturn(true);
            when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID))
                    .thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldAllowReproveJourneyToContinueAndSendAisAuditEvent() {
            // Arrange
            when(configService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(false);
            when(mockAisService.fetchAisInterventionType(TEST_USER_ID))
                    .thenReturn(AisInterventionType.AIS_FORCED_USER_IDENTITY_VERIFY);
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, List.of(), false))
                    .thenReturn(emptyAsyncCriStatus);

            // Act
            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            // Assert
            verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
            var auditEvent = auditEventArgumentCaptor.getValue();
            var extension = (AuditExtensionAccountIntervention) auditEvent.getExtensions();
            assertEquals(AuditEventTypes.IPV_ACCOUNT_INTERVENTION_START, auditEvent.getEventName());
            assertEquals("reprove_identity", extension.getType());
            assertNull(extension.getSuccess());
            assertTrue(clientOAuthSessionItem.getReproveIdentity());
            assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
        }

        @ParameterizedTest
        @MethodSource("getFetchedAccountInterventionStateWithTypeForInvalidJourney")
        void shouldInvalidSession(AisInterventionType aisInterventionType) {
            // Arrange
            when(mockAisService.fetchAisInterventionType(TEST_USER_ID))
                    .thenReturn(aisInterventionType);

            // Act
            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            // Assert
            verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(JOURNEY_ACCOUNT_INTERVENTION, journeyResponse);
        }

        private static Stream<Arguments>
                getFetchedAccountInterventionStateWithTypeForInvalidJourney() {
            return Stream.of(
                    Arguments.of(AIS_ACCOUNT_BLOCKED),
                    Arguments.of(AIS_ACCOUNT_SUSPENDED),
                    Arguments.of(AIS_FORCED_USER_PASSWORD_RESET));
        }
    }

    @Test
    void shouldNotInvalidateSiIfFeatureFlagDisabled() throws Exception {
        when(configService.enabled(AIS_ENABLED)).thenReturn(false);
        when(configService.enabled(STORED_IDENTITY_SERVICE)).thenReturn(false);
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(emptyAsyncCriStatus);

        checkExistingIdentityHandler.handleRequest(event, context);

        verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
        verify(mockEvcsService, times(0)).invalidateStoredIdentityRecord(TEST_USER_ID);
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSessionWithRetry(anyString()))
                .thenThrow(new RuntimeException("Test error"));

        var logCollector = LogCollector.getLogCollectorFor(CheckExistingIdentityHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> checkExistingIdentityHandler.handleRequest(event, context),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessages = logCollector.getLogMessages();
        var logMessage =
                logMessages.stream()
                        .filter(m -> m.contains("Unhandled lambda exception"))
                        .toList()
                        .getFirst();
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private <T> T toResponseClass(Map<String, Object> handlerOutput, Class<T> responseClass) {
        return OBJECT_MAPPER.convertValue(handlerOutput, responseClass);
    }

    private static VotMatchingResult buildMatchResultFor(Vot vot, Gpg45Profile profile) {
        return new VotMatchingResult(
                Optional.of(
                        new VotMatchingResult.VotAndProfile(
                                vot, profile == null ? Optional.empty() : Optional.of(profile))),
                Optional.of(
                        new VotMatchingResult.VotAndProfile(
                                vot, profile == null ? Optional.empty() : Optional.of(profile))),
                Gpg45Scores.builder().build());
    }
}
