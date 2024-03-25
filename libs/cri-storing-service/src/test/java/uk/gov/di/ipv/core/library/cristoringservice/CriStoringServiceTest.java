package uk.gov.di.ipv.core.library.cristoringservice;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.exceptions.AuditExtensionException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.dto.VerifiableCredentialResponseDto;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.text.ParseException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;

@ExtendWith(MockitoExtension.class)
class CriStoringServiceTest {
    private static final String TEST_CRI_ID = "test_cri_id";
    private static final String TEST_AUTHORISATION_CODE = "test_authorisation_code";
    private static final String TEST_IPV_SESSION_ID = "test_ipv_Session_id";
    private static final String TEST_CRI_OAUTH_SESSION_ID = "test_cri_oauth_session_id";
    private static final String TEST_USER_ID = "test_user_id";
    @Mock private ConfigService mockConfigService;
    @Mock private AuditService mockAuditService;
    @Mock private CriResponseService mockCriResponseService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private CiMitService mockCiMitService;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @InjectMocks private CriStoringService criStoringService;
    @Captor private ArgumentCaptor<String> userIdCaptor;
    @Captor private ArgumentCaptor<String> criIdCaptor;
    @Captor private ArgumentCaptor<String> vcResponseCaptor;
    @Captor private ArgumentCaptor<String> criOAuthSessionIdCaptor;
    @Captor private ArgumentCaptor<AuditEvent> auditEventCaptor;
    @Captor private ArgumentCaptor<VerifiableCredential> vcCaptor;
    @Captor private ArgumentCaptor<List<VerifiableCredential>> vcListCaptor;

    @BeforeEach
    void setUp() {
        criStoringService =
                new CriStoringService(
                        mockConfigService,
                        mockAuditService,
                        mockCriResponseService,
                        mockVerifiableCredentialService,
                        mockCiMitService);
    }

    @Test
    void storeCriResponseShouldStoreResponseAndSendAuditEvent()
            throws SqsException, JsonProcessingException {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();

        // Act
        criStoringService.storeCriResponse(callbackRequest, clientOAuthSessionItem);

        // Assert
        verify(mockCriResponseService)
                .persistCriResponse(
                        userIdCaptor.capture(),
                        criIdCaptor.capture(),
                        vcResponseCaptor.capture(),
                        criOAuthSessionIdCaptor.capture(),
                        eq(CriResponseService.STATUS_PENDING));

        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());

        // Assert
        assertEquals(callbackRequest.getCredentialIssuerId(), criIdCaptor.getValue());
        assertEquals(callbackRequest.getState(), criOAuthSessionIdCaptor.getValue());
        assertEquals(clientOAuthSessionItem.getUserId(), userIdCaptor.getValue());
        var expectedVcResponseDto =
                VerifiableCredentialResponseDto.builder()
                        .userId(clientOAuthSessionItem.getUserId())
                        .credentialStatus(VerifiableCredentialStatus.PENDING.getStatus())
                        .build();
        var expectedSerializedVcResponse =
                new ObjectMapper().writeValueAsString(expectedVcResponseDto);
        assertEquals(expectedSerializedVcResponse, vcResponseCaptor.getValue());
        var sentAuditEvent = auditEventCaptor.getValue();
        assertEquals(
                AuditEventTypes.IPV_CORE_CRI_RESOURCE_RETRIEVED, sentAuditEvent.getEventName());
    }

    @Test
    void storeCriResponseShouldThrowSqsException() throws SqsException {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        doThrow(new SqsException("")).when(mockAuditService).sendAuditEvent(any(AuditEvent.class));

        // Act & Assert
        assertThrows(
                SqsException.class,
                () -> criStoringService.storeCriResponse(callbackRequest, clientOAuthSessionItem));
    }

    @Test
    void storeVcsShouldProcessVcsAndSendAuditEvents()
            throws ParseException, SqsException, VerifiableCredentialException,
                    CiPostMitigationsException, CiPutException, AuditExtensionException,
                    UnrecognisedVotException, CredentialParseException {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var vc = PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();

        // Act
        criStoringService.storeVcs(
                callbackRequest.getCredentialIssuerId(),
                callbackRequest.getIpAddress(),
                List.of(vc),
                clientOAuthSessionItem,
                mockIpvSessionItem);

        // Assert
        verify(mockCiMitService)
                .submitVC(
                        vcCaptor.capture(),
                        eq(clientOAuthSessionItem.getGovukSigninJourneyId()),
                        eq(callbackRequest.getIpAddress()));
        assertEquals(vc, vcCaptor.getValue());

        verify(mockCiMitService)
                .submitMitigatingVcList(
                        vcListCaptor.capture(),
                        eq(clientOAuthSessionItem.getGovukSigninJourneyId()),
                        eq(callbackRequest.getIpAddress()));
        assertEquals(List.of(vc), vcListCaptor.getValue());

        assertEquals(vc, vcCaptor.getValue());

        verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
        var capturedAuditEvents = auditEventCaptor.getAllValues();
        var firstAuditEvent = capturedAuditEvents.get(0);
        assertEquals(AuditEventTypes.IPV_VC_RECEIVED, firstAuditEvent.getEventName());
        var secondAuditEvent = capturedAuditEvents.get(1);
        assertEquals(
                AuditEventTypes.IPV_CORE_CRI_RESOURCE_RETRIEVED, secondAuditEvent.getEventName());

        verify(mockIpvSessionItem).addVcReceivedThisSession(vc);
        verify(mockIpvSessionItem).setRiskAssessmentCredential(vc.getVcString());
    }

    @Test
    void storeVcsShouldHandleEmptyVcList()
            throws SqsException, VerifiableCredentialException, CiPostMitigationsException,
                    CiPutException, ParseException, AuditExtensionException,
                    UnrecognisedVotException {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();

        // Act
        criStoringService.storeVcs(
                callbackRequest.getCredentialIssuerId(),
                callbackRequest.getIpAddress(),
                List.of(),
                clientOAuthSessionItem,
                mockIpvSessionItem);

        // Assert
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        var capturedEvent = auditEventCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_CORE_CRI_RESOURCE_RETRIEVED, capturedEvent.getEventName());
    }

    @Test
    void storeVcsShouldThrowCiPutExceptionWhenCiSubmissionFails() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        doThrow(new CiPutException(""))
                .when(mockCiMitService)
                .submitVC(any(VerifiableCredential.class), any(), any());

        // Act & Assert
        assertThrows(
                CiPutException.class,
                () ->
                        criStoringService.storeVcs(
                                callbackRequest.getCredentialIssuerId(),
                                callbackRequest.getIpAddress(),
                                List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC),
                                clientOAuthSessionItem,
                                mockIpvSessionItem));

        verify(mockIpvSessionItem, never()).setVcReceivedThisSession(any());
    }

    @Test
    void storeVcsShouldThrowCiPostMitigationsExceptionWhenCiMitigationListSubmissionFails()
            throws CiPostMitigationsException {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        doThrow(new CiPostMitigationsException(""))
                .when(mockCiMitService)
                .submitMitigatingVcList(any(), any(), any());

        // Act & Assert
        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        criStoringService.storeVcs(
                                callbackRequest.getCredentialIssuerId(),
                                callbackRequest.getIpAddress(),
                                List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC),
                                clientOAuthSessionItem,
                                mockIpvSessionItem));

        verify(mockIpvSessionItem, never()).setVcReceivedThisSession(any());
    }

    @Test
    void storeVcsShouldThrowSqsExceptionWhenAuditEventFailsToSend() throws SqsException {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        doThrow(new SqsException("")).when(mockAuditService).sendAuditEvent(any(AuditEvent.class));

        // Act & Assert
        assertThrows(
                SqsException.class,
                () ->
                        criStoringService.storeVcs(
                                callbackRequest.getCredentialIssuerId(),
                                callbackRequest.getIpAddress(),
                                List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC),
                                clientOAuthSessionItem,
                                mockIpvSessionItem));

        verify(mockIpvSessionItem, never()).setVcReceivedThisSession(any());
    }

    private CriCallbackRequest buildValidCallbackRequest() {
        return CriCallbackRequest.builder()
                .ipvSessionId(TEST_IPV_SESSION_ID)
                .credentialIssuerId(TEST_CRI_ID)
                .authorizationCode(TEST_AUTHORISATION_CODE)
                .state(TEST_CRI_OAUTH_SESSION_ID)
                .build();
    }

    private ClientOAuthSessionItem buildValidClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder().userId(TEST_USER_ID).build();
    }
}
