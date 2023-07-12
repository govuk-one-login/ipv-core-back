package uk.gov.di.ipv.core.checkexistingidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.*;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorMitigationDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_F2F_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_VERIFICATION_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1B_DCMAW_VC;

@ExtendWith(MockitoExtension.class)
class CheckExistingIdentityHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";

    private static final String TEST_FEATURE_SET = "test-feature-set";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.generate();

    private static final String TEST_JOURNEY = "journey/check-existing-identity";

    private static final List<String> CREDENTIALS =
            List.of(
                    M1A_PASSPORT_VC,
                    M1A_ADDRESS_VC,
                    M1A_FRAUD_VC,
                    M1A_VERIFICATION_VC,
                    M1B_DCMAW_VC);
    private static final List<String> CRI_RESPONSE = List.of(M1A_F2F_VC);
    private static CredentialIssuerConfig addressConfig = null;
    private static CredentialIssuerConfig claimedIdentityConfig = null;
    private static final List<SignedJWT> PARSED_CREDENTIALS = new ArrayList<>();

    private static final List<Gpg45Profile> ACCEPTED_PROFILES =
            List.of(Gpg45Profile.M1A, Gpg45Profile.M1B);
    private static final JourneyResponse JOURNEY_REUSE = new JourneyResponse("/journey/reuse");
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse("/journey/next");
    private static final JourneyResponse JOURNEY_RESET_IDENTITY =
            new JourneyResponse("/journey/reset-identity");
    private static final JourneyResponse JOURNEY_PENDING = new JourneyResponse("/journey/pending");
    private static final ObjectMapper mapper = new ObjectMapper();

    static {
        try {
            addressConfig =
                    new CredentialIssuerConfig(
                            new URI("http://example.com/token"),
                            new URI("http://example.com/credential"),
                            new URI("http://example.com/authorize"),
                            "ipv-core",
                            "test-jwk",
                            "test-encryption-jwk",
                            "test-audience",
                            new URI("http://example.com/redirect"),
                            true);

            claimedIdentityConfig =
                    new CredentialIssuerConfig(
                            new URI("http://example.com/token"),
                            new URI("http://example.com/credential"),
                            new URI("http://example.com/authorize"),
                            "ipv-core",
                            "test-jwk",
                            "test-encryption-jwk",
                            "test-claimed-identity",
                            new URI("http://example.com/redirect"),
                            true);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private CriResponseService criResponseService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @Mock private CiStorageService ciStorageService;
    @Mock private ConfigService configService;
    @Mock private AuditService auditService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @InjectMocks private CheckExistingIdentityHandler checkExistingIdentityHandler;

    private JourneyRequest event;
    private IpvSessionItem ipvSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeAll
    static void setUp() throws Exception {
        for (String cred : CREDENTIALS) {
            PARSED_CREDENTIALS.add(SignedJWT.parse(cred));
        }
    }

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

        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setIpvSessionId(TEST_SESSION_ID);
        ipvSessionItem.setContraIndicatorMitigationDetails(
                List.of(new ContraIndicatorMitigationDetailsDto("A01")));

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
    void shouldReturnJourneyReuseResponseIfScoresSatisfyM1AGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(Gpg45Profile.M1A));
        when(configService.getCredentialIssuerActiveConnectionConfig("address"))
                .thenReturn(addressConfig);
        when(configService.getCredentialIssuerActiveConnectionConfig("claimedIdentity"))
                .thenReturn(claimedIdentityConfig);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse = handleRequest(event, context, JourneyResponse.class);

        assertEquals(JOURNEY_REUSE, journeyResponse);

        verify(userIdentityService, never()).deleteVcStoreItems(TEST_USER_ID);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(2)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());
        assertEquals(
                AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                auditEventArgumentCaptor.getAllValues().get(1).getEventName());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnJourneyReuseResponseIfScoresSatisfyM1BGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(criResponseService.userHasFaceToFaceRequest(TEST_USER_ID)).thenReturn(false);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(Gpg45Profile.M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse = handleRequest(event, context, JourneyResponse.class);
        assertEquals(JOURNEY_REUSE, journeyResponse);

        verify(userIdentityService, never()).deleteVcStoreItems(TEST_USER_ID);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(2)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                auditEventArgumentCaptor.getValue().getEventName());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnJourneyResetIdentityResponseIfScoresDoNotSatisfyM1AGpg45Profile()
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(criResponseService.userHasFaceToFaceRequest(TEST_USER_ID)).thenReturn(false);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenCallRealMethod();
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse = handleRequest(event, context, JourneyResponse.class);
        assertEquals(JOURNEY_RESET_IDENTITY, journeyResponse);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_IDENTITY_REUSE_RESET,
                auditEventArgumentCaptor.getValue().getEventName());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnPyiNoMatchIfVcsFailCiScoreCheck() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(criResponseService.userHasFaceToFaceRequest(TEST_USER_ID)).thenReturn(false);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenReturn(Optional.of(new JourneyResponse("/journey/pyi-no-match")));
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenCallRealMethod();
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse = handleRequest(event, context, JourneyResponse.class);
        assertEquals("/journey/pyi-no-match", journeyResponse.getJourney());

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnJourneyErrorIfUnrecognisedCiReceived() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(criResponseService.userHasFaceToFaceRequest(TEST_USER_ID)).thenReturn(false);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenThrow(new UnrecognisedCiException("Not recognised"));
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenCallRealMethod();
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse = handleRequest(event, context, JourneyErrorResponse.class);
        assertEquals("/journey/error", journeyResponse.getJourney());
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, journeyResponse.getStatusCode());
        assertEquals(ErrorResponse.UNRECOGNISED_CI_CODE.getCode(), journeyResponse.getCode());
        assertEquals(ErrorResponse.UNRECOGNISED_CI_CODE.getMessage(), journeyResponse.getMessage());

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldNotSendAuditEventIfNewUser() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID))
                .thenReturn(Collections.emptyList());
        when(criResponseService.userHasFaceToFaceRequest(TEST_USER_ID)).thenReturn(false);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenCallRealMethod();
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse = handleRequest(event, context, JourneyResponse.class);
        assertEquals("/journey/next", journeyResponse.getJourney());
        verify(userIdentityService, never()).deleteVcStoreItems(TEST_USER_ID);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn400IfSessionIdNotInHeader() throws IOException {
        JourneyRequest eventWithoutHeaders = JourneyRequest.builder().build();

        var journeyResponse =
                handleRequest(eventWithoutHeaders, context, JourneyErrorResponse.class);
        assertEquals("/journey/error", journeyResponse.getJourney());

        assertEquals(HttpStatus.SC_BAD_REQUEST, journeyResponse.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), journeyResponse.getCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), journeyResponse.getMessage());
        verify(clientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnPendingResponseIfFaceToFaceVerificationIsPending() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getVcStoreItem(TEST_USER_ID, F2F_CRI)).thenReturn(null);
        when(criResponseService.userHasFaceToFaceRequest(TEST_USER_ID)).thenReturn(true);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse = handleRequest(event, context, JourneyResponse.class);
        assertEquals(JOURNEY_PENDING, journeyResponse);
        verify(userIdentityService, times(0)).deleteVcStoreItems(TEST_USER_ID);
    }

    @Test
    void shouldReturn500IfFailedToParseCredentials() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.buildScore(any())).thenThrow(new ParseException("Whoops", 0));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse = handleRequest(event, context, JourneyErrorResponse.class);
        assertEquals("/journey/error", journeyResponse.getJourney());

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, journeyResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode(),
                journeyResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(),
                journeyResponse.getMessage());

        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfCredentialOfUnknownType() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.buildScore(any())).thenThrow(new UnknownEvidenceTypeException());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse = handleRequest(event, context, JourneyErrorResponse.class);
        assertEquals("/journey/error", journeyResponse.getJourney());

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, journeyResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getCode(),
                journeyResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getMessage(),
                journeyResponse.getMessage());

        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
        verify(criResponseService).userHasFaceToFaceRequest(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfFailedToRetrieveCisFromStorageSystem() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(criResponseService.userHasFaceToFaceRequest(TEST_USER_ID)).thenReturn(false);
        when(ciStorageService.getCIs(anyString(), anyString(), anyString()))
                .thenThrow(CiRetrievalException.class);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse = handleRequest(event, context, JourneyErrorResponse.class);
        assertEquals("/journey/error", journeyResponse.getJourney());

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, journeyResponse.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_STORED_CIS.getCode(), journeyResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GET_STORED_CIS.getMessage(), journeyResponse.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfFailedToSendAuditEvent() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(Gpg45Profile.M1A));

        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        doThrow(new SqsException("test error"))
                .when(auditService)
                .sendAuditEvent((AuditEvent) any());

        var journeyResponse = handleRequest(event, context, JourneyErrorResponse.class);
        assertEquals("/journey/error", journeyResponse.getJourney());

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, journeyResponse.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT.getCode(), journeyResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT.getMessage(),
                journeyResponse.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    private <T extends BaseResponse> T handleRequest(
            JourneyRequest request, Context context, Class<T> classType) throws IOException {
        try (var inputStream =
                        new ByteArrayInputStream(mapper.writeValueAsString(request).getBytes());
                var outputStream = new ByteArrayOutputStream()) {
            checkExistingIdentityHandler.handleRequest(inputStream, outputStream, context);
            return mapper.readValue(outputStream.toString(), classType);
        }
    }
}
