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
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.AuditExtensionGpg45ProfileMatched;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.BaseResponse;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorMitigationDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC_WITH_CI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_VERIFICATION_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1a_FRAUD_VC_WITH_CI_A01;

@ExtendWith(MockitoExtension.class)
class EvaluateGpg45ScoreHandlerTest {
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
    private static final String A01 = "A01";
    public static CredentialIssuerConfig addressConfig = null;
    private static final List<SignedJWT> PARSED_CREDENTIALS = new ArrayList<>();
    private static final List<Gpg45Profile> ACCEPTED_PROFILES =
            List.of(Gpg45Profile.M1A, Gpg45Profile.M1B);
    private static final JourneyResponse JOURNEY_END = new JourneyResponse("/journey/end");
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse("/journey/next");
    private static final String JOURNEY_PYI_NO_MATCH = "/journey/pyi-no-match";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.generate();
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
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @Mock private CiStorageService ciStorageService;
    @Mock private ConfigService configService;
    @Mock private AuditService auditService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @InjectMocks private EvaluateGpg45ScoresHandler evaluateGpg45ScoresHandler;

    private IpvSessionItem ipvSessionItem;
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
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setIpvSessionId(TEST_SESSION_ID);
        ipvSessionItem.setContraIndicatorMitigationDetails(
                List.of(new ContraIndicatorMitigationDetailsDto(A01)));

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
        when(configService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(addressConfig);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(Gpg45Profile.M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any(), any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any(), any()))
                .thenReturn(true);

        var response = handleRequest(request, context, JourneyResponse.class);

        assertEquals(JOURNEY_END.getJourney(), response.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem updatedSessionItem = ipvSessionItemArgumentCaptor.getValue();

        List<VcStatusDto> currentVcStatuses = updatedSessionItem.getCurrentVcStatuses();
        assertEquals(5, currentVcStatuses.size());

        assertTrue(currentVcStatuses.get(0).getIsSuccessfulVc());
        assertEquals(
                "https://review-p.integration.account.gov.uk",
                currentVcStatuses.get(0).getCriIss());
        assertFalse(currentVcStatuses.get(1).getIsSuccessfulVc());
        assertEquals(
                "https://review-a.integration.account.gov.uk",
                currentVcStatuses.get(1).getCriIss());
        assertTrue(currentVcStatuses.get(2).getIsSuccessfulVc());
        assertEquals(
                "https://review-f.integration.account.gov.uk",
                currentVcStatuses.get(2).getCriIss());
        assertTrue(currentVcStatuses.get(3).getIsSuccessfulVc());
        assertEquals(
                "https://review-k.integration.account.gov.uk",
                currentVcStatuses.get(3).getCriIss());
        assertTrue(currentVcStatuses.get(4).getIsSuccessfulVc());
        assertEquals("test-dcmaw-iss", currentVcStatuses.get(4).getCriIss());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnJourneySessionEndIfScoresSatisfyM1BGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(Gpg45Profile.M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any(), any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any(), any()))
                .thenReturn(true);

        var response = handleRequest(request, context, JourneyResponse.class);

        assertEquals(JOURNEY_END.getJourney(), response.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnJourneyNextIfScoresDoNotSatisfyM1AGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.empty());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any(), any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any(), any()))
                .thenReturn(true);

        var response = handleRequest(request, context, JourneyResponse.class);

        assertEquals(JOURNEY_NEXT.getJourney(), response.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn400IfSessionIdNotInRequest() throws Exception {
        JourneyRequest requestWithoutSessionId =
                JourneyRequest.builder().ipAddress(TEST_CLIENT_SOURCE_IP).build();

        var response = handleRequest(requestWithoutSessionId, context, JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), response.getCode());
        verify(clientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfFailedToParseCredentials() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.buildScore(any())).thenThrow(new ParseException("Whoops", 0));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var response = handleRequest(request, context, JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode(), response.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(),
                response.getMessage());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfCredentialOfUnknownType() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.buildScore(any())).thenThrow(new UnknownEvidenceTypeException());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var response = handleRequest(request, context, JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getCode(), response.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getMessage(),
                response.getMessage());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnJourneyErrorJourneyResponseIfCiAreFoundOnVcs() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenReturn(Optional.of(new JourneyResponse(JOURNEY_PYI_NO_MATCH)));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var response = handleRequest(request, context, JourneyResponse.class);

        assertEquals(JOURNEY_PYI_NO_MATCH, response.getJourney());
    }

    @Test
    void shouldReturn500IfFailedToRetrieveCisFromStorageSystem() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(ciStorageService.getCIs(anyString(), anyString(), anyString()))
                .thenThrow(CiRetrievalException.class);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var response = handleRequest(request, context, JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_STORED_CIS.getCode(), response.getCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_STORED_CIS.getMessage(), response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldSendAuditEventWhenProfileMatched() throws Exception {
        List<SignedJWT> parsedM1ACreds =
                List.of(
                        SignedJWT.parse(M1A_PASSPORT_VC),
                        SignedJWT.parse(M1A_ADDRESS_VC),
                        SignedJWT.parse(M1A_FRAUD_VC),
                        SignedJWT.parse(M1A_VERIFICATION_VC));
        when(configService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(addressConfig);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(parsedM1ACreds);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(Gpg45Profile.M1A));
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 2));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any(), any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any(), any()))
                .thenReturn(true);

        handleRequest(request, context, JourneyResponse.class);

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
        assertEquals(Gpg45Profile.M1A, extension.getGpg45Profile());
        assertEquals(new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 2), extension.getGpg45Scores());
        assertEquals(
                List.of("123ab93d-3a43-46ef-a2c1-3c6444206408", "RB000103490087", "abc1234"),
                extension.getVcTxnIds());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldRecordCiToBeMitigatedInSessionWhenNewCiIsReceived() throws Exception {
        List<SignedJWT> parsedM1ACreds =
                List.of(
                        SignedJWT.parse(M1A_PASSPORT_VC),
                        SignedJWT.parse(M1A_ADDRESS_VC),
                        SignedJWT.parse(M1a_FRAUD_VC_WITH_CI_A01));
        when(configService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(addressConfig);
        when(configService.getSsmParameter(ConfigurationVariable.CI_MITIGATION_JOURNEYS_ENABLED))
                .thenReturn("true");
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(parsedM1ACreds);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any(), any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any(), any()))
                .thenReturn(true);

        handleRequest(request, context, JourneyResponse.class);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());

        IpvSessionItem ipvSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertEquals(1, ipvSessionItem.getContraIndicatorMitigationDetails().size());
        assertEquals(A01, ipvSessionItem.getContraIndicatorMitigationDetails().get(0).getCi());
        assertEquals(
                Collections.emptyList(),
                ipvSessionItem
                        .getContraIndicatorMitigationDetails()
                        .get(0)
                        .getMitigationJourneys());
        assertTrue(ipvSessionItem.getContraIndicatorMitigationDetails().get(0).isMitigatable());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldNotCheckGpg45ProfileIfNewCiIsReceived() throws Exception {
        List<SignedJWT> parsedM1ACreds =
                List.of(
                        SignedJWT.parse(M1A_PASSPORT_VC_WITH_CI),
                        SignedJWT.parse(M1A_ADDRESS_VC),
                        SignedJWT.parse(M1a_FRAUD_VC_WITH_CI_A01));
        when(configService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(addressConfig);
        when(configService.getSsmParameter(ConfigurationVariable.CI_MITIGATION_JOURNEYS_ENABLED))
                .thenReturn("true");
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(parsedM1ACreds);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(ciStorageService.getCIs(any(), any(), any()))
                .thenReturn(
                        List.of(
                                new ContraIndicatorItem(
                                        "test-user",
                                        "1234",
                                        "test-iss",
                                        "1234",
                                        A01,
                                        "1234",
                                        "1234"),
                                new ContraIndicatorItem(
                                        "test-user",
                                        "1234",
                                        "test-iss",
                                        "1234",
                                        "D02",
                                        "1234",
                                        "1234")));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any(), any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any(), any()))
                .thenReturn(true);

        handleRequest(request, context, JourneyResponse.class);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService, times(2))
                .updateIpvSession(ipvSessionItemArgumentCaptor.capture());

        IpvSessionItem ipvSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertEquals(2, ipvSessionItem.getContraIndicatorMitigationDetails().size());
        assertEquals(A01, ipvSessionItem.getContraIndicatorMitigationDetails().get(0).getCi());
        assertEquals(
                Collections.emptyList(),
                ipvSessionItem
                        .getContraIndicatorMitigationDetails()
                        .get(0)
                        .getMitigationJourneys());
        assertTrue(ipvSessionItem.getContraIndicatorMitigationDetails().get(0).isMitigatable());

        verify(gpg45ProfileEvaluator, never()).getFirstMatchingProfile(any(), any());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldNotCheckGpg45ProfileIfNewCiIsReceivedAndNoPreviousMitigation() throws Exception {
        List<SignedJWT> parsedM1ACreds =
                List.of(
                        SignedJWT.parse(M1A_PASSPORT_VC_WITH_CI),
                        SignedJWT.parse(M1A_ADDRESS_VC),
                        SignedJWT.parse(M1a_FRAUD_VC_WITH_CI_A01));
        when(configService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(addressConfig);
        when(configService.getSsmParameter(ConfigurationVariable.CI_MITIGATION_JOURNEYS_ENABLED))
                .thenReturn("true");
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(parsedM1ACreds);
        ipvSessionItem.setContraIndicatorMitigationDetails(null);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(ciStorageService.getCIs(any(), any(), any()))
                .thenReturn(
                        List.of(
                                new ContraIndicatorItem(
                                        "test-user",
                                        "1234",
                                        "test-iss",
                                        "1234",
                                        A01,
                                        "1234",
                                        "1234")));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any(), any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any(), any()))
                .thenReturn(true);

        handleRequest(request, context, JourneyResponse.class);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService, times(2))
                .updateIpvSession(ipvSessionItemArgumentCaptor.capture());

        IpvSessionItem ipvSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertEquals(1, ipvSessionItem.getContraIndicatorMitigationDetails().size());
        assertEquals(A01, ipvSessionItem.getContraIndicatorMitigationDetails().get(0).getCi());
        assertEquals(
                Collections.emptyList(),
                ipvSessionItem
                        .getContraIndicatorMitigationDetails()
                        .get(0)
                        .getMitigationJourneys());
        assertTrue(ipvSessionItem.getContraIndicatorMitigationDetails().get(0).isMitigatable());

        verify(gpg45ProfileEvaluator, never()).getFirstMatchingProfile(any(), any());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldNotCheckGpg45ProfileIfMitigationInProgress() throws Exception {
        List<SignedJWT> parsedM1ACreds =
                List.of(SignedJWT.parse(M1A_PASSPORT_VC), SignedJWT.parse(M1A_ADDRESS_VC));
        when(configService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(addressConfig);
        when(configService.getSsmParameter(ConfigurationVariable.CI_MITIGATION_JOURNEYS_ENABLED))
                .thenReturn("true");
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(parsedM1ACreds);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(ciStorageService.getCIs(any(), any(), any()))
                .thenReturn(
                        List.of(
                                new ContraIndicatorItem(
                                        "test-user",
                                        "1234",
                                        "test-iss",
                                        "1234",
                                        A01,
                                        "1234",
                                        "1234")));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any(), any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any(), any()))
                .thenReturn(true);

        handleRequest(request, context, JourneyResponse.class);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());

        IpvSessionItem ipvSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertEquals(1, ipvSessionItem.getContraIndicatorMitigationDetails().size());
        assertEquals(A01, ipvSessionItem.getContraIndicatorMitigationDetails().get(0).getCi());
        assertEquals(
                Collections.emptyList(),
                ipvSessionItem
                        .getContraIndicatorMitigationDetails()
                        .get(0)
                        .getMitigationJourneys());
        assertTrue(ipvSessionItem.getContraIndicatorMitigationDetails().get(0).isMitigatable());

        verify(gpg45ProfileEvaluator, never()).getFirstMatchingProfile(any(), any());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldCheckGpg45ProfileIfMitigationHasCompleted() throws Exception {
        when(configService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(addressConfig);
        when(configService.getSsmParameter(ConfigurationVariable.CI_MITIGATION_JOURNEYS_ENABLED))
                .thenReturn("true");
        ipvSessionItem.setContraIndicatorMitigationDetails(
                List.of(
                        new ContraIndicatorMitigationDetailsDto(
                                A01, Collections.emptyList(), false)));
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(Gpg45Profile.M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any(), any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any(), any()))
                .thenReturn(true);

        var response = handleRequest(request, context, JourneyResponse.class);

        assertEquals(JOURNEY_END.getJourney(), response.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem updatedSessionItem = ipvSessionItemArgumentCaptor.getValue();

        List<VcStatusDto> currentVcStatuses = updatedSessionItem.getCurrentVcStatuses();
        assertEquals(5, currentVcStatuses.size());

        assertTrue(currentVcStatuses.get(0).getIsSuccessfulVc());
        assertEquals(
                "https://review-p.integration.account.gov.uk",
                currentVcStatuses.get(0).getCriIss());
        assertFalse(currentVcStatuses.get(1).getIsSuccessfulVc());
        assertEquals(
                "https://review-a.integration.account.gov.uk",
                currentVcStatuses.get(1).getCriIss());
        assertTrue(currentVcStatuses.get(2).getIsSuccessfulVc());
        assertEquals(
                "https://review-f.integration.account.gov.uk",
                currentVcStatuses.get(2).getCriIss());
        assertTrue(currentVcStatuses.get(3).getIsSuccessfulVc());
        assertEquals(
                "https://review-k.integration.account.gov.uk",
                currentVcStatuses.get(3).getCriIss());
        assertTrue(currentVcStatuses.get(4).getIsSuccessfulVc());
        assertEquals("test-dcmaw-iss", currentVcStatuses.get(4).getCriIss());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldCheckGpg45ProfileWhenNoNewCiAndNoCurrentMitigationInProgress() throws Exception {
        when(configService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(addressConfig);
        when(configService.getSsmParameter(ConfigurationVariable.CI_MITIGATION_JOURNEYS_ENABLED))
                .thenReturn("true");
        ipvSessionItem.setContraIndicatorMitigationDetails(Collections.emptyList());
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any()))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(Gpg45Profile.M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any(), any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any(), any()))
                .thenReturn(true);

        var response = handleRequest(request, context, JourneyResponse.class);

        assertEquals(JOURNEY_END.getJourney(), response.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem updatedSessionItem = ipvSessionItemArgumentCaptor.getValue();

        List<VcStatusDto> currentVcStatuses = updatedSessionItem.getCurrentVcStatuses();
        assertEquals(5, currentVcStatuses.size());

        assertTrue(currentVcStatuses.get(0).getIsSuccessfulVc());
        assertEquals(
                "https://review-p.integration.account.gov.uk",
                currentVcStatuses.get(0).getCriIss());
        assertFalse(currentVcStatuses.get(1).getIsSuccessfulVc());
        assertEquals(
                "https://review-a.integration.account.gov.uk",
                currentVcStatuses.get(1).getCriIss());
        assertTrue(currentVcStatuses.get(2).getIsSuccessfulVc());
        assertEquals(
                "https://review-f.integration.account.gov.uk",
                currentVcStatuses.get(2).getCriIss());
        assertTrue(currentVcStatuses.get(3).getIsSuccessfulVc());
        assertEquals(
                "https://review-k.integration.account.gov.uk",
                currentVcStatuses.get(3).getCriIss());
        assertTrue(currentVcStatuses.get(4).getIsSuccessfulVc());
        assertEquals("test-dcmaw-iss", currentVcStatuses.get(4).getCriIss());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturnPyiNoMatchIfFailedDueToNameCorrelationIssues() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any(), any()))
                .thenReturn(false);

        var response = handleRequest(request, context, JourneyResponse.class);

        assertEquals(JOURNEY_PYI_NO_MATCH, response.getJourney());

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(userIdentityService, times(1))
                .checkNameAndFamilyNameCorrelationInCredentials(any(), any());
        verify(userIdentityService, times(0)).checkBirthDateCorrelationInCredentials(any(), any());
    }

    @Test
    void shouldReturnPyiNoMatchIfFailedDueToBirthdateCorrelationIssues() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(any(), any()))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(any(), any()))
                .thenReturn(false);

        var response = handleRequest(request, context, JourneyResponse.class);

        assertEquals(JOURNEY_PYI_NO_MATCH, response.getJourney());

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(userIdentityService, times(1)).checkBirthDateCorrelationInCredentials(any(), any());
    }

    private <T extends BaseResponse> T handleRequest(
            JourneyRequest request, Context context, Class<T> classType) throws IOException {
        try (var inputStream =
                        new ByteArrayInputStream(mapper.writeValueAsString(request).getBytes());
                var outputStream = new ByteArrayOutputStream()) {
            evaluateGpg45ScoresHandler.handleRequest(inputStream, outputStream, context);
            return mapper.readValue(outputStream.toString(), classType);
        }
    }
}
