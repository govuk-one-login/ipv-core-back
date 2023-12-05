package uk.gov.di.ipv.core.library.cristoringservice;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
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
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;

@ExtendWith(MockitoExtension.class)
public class CriStoringServiceTest {
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
    @Mock private SignedJWT mockSignedJWT;
    @InjectMocks private CriStoringService criStoringService;
    @Captor private ArgumentCaptor<String> userIdCaptor;
    @Captor private ArgumentCaptor<String> criIdCaptor;
    @Captor private ArgumentCaptor<String> vcResponseCaptor;
    @Captor private ArgumentCaptor<String> criOAuthSessionIdCaptor;
    @Captor private ArgumentCaptor<AuditEvent> auditEventCaptor;
    @Captor private ArgumentCaptor<SignedJWT> signedJwtCaptor;
    @Captor private ArgumentCaptor<List<String>> vcListCaptor;

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
    void storeCriResponseShouldStoreResponseAndSendAuditEvent() throws Exception {
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
    void storeCriResponseShouldThrowSqsException() throws Exception {
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
    void storeCreatedVcsShouldProcessVcsAndSendAuditEvents() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var signedJWT = SignedJWT.parse(M1A_PASSPORT_VC);
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();

        // Act
        criStoringService.storeVcs(
                callbackRequest.getCredentialIssuerId(),
                callbackRequest.getIpAddress(),
                callbackRequest.getIpvSessionId(),
                List.of(signedJWT),
                clientOAuthSessionItem);

        // Assert
        verify(mockCiMitService)
                .submitVC(
                        signedJwtCaptor.capture(),
                        eq(clientOAuthSessionItem.getGovukSigninJourneyId()),
                        eq(callbackRequest.getIpAddress()));
        assertEquals(signedJWT, signedJwtCaptor.getValue());

        verify(mockCiMitService)
                .submitMitigatingVcList(
                        vcListCaptor.capture(),
                        eq(clientOAuthSessionItem.getGovukSigninJourneyId()),
                        eq(callbackRequest.getIpAddress()));
        assertEquals(List.of(signedJWT.serialize()), vcListCaptor.getValue());

        verify(mockVerifiableCredentialService)
                .persistUserCredentials(
                        signedJwtCaptor.capture(),
                        eq(callbackRequest.getCredentialIssuerId()),
                        eq(clientOAuthSessionItem.getUserId()));
        assertEquals(signedJWT, signedJwtCaptor.getValue());

        verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
        var capturedAuditEvents = auditEventCaptor.getAllValues();
        var firstAuditEvent = capturedAuditEvents.get(0);
        assertEquals(AuditEventTypes.IPV_VC_RECEIVED, firstAuditEvent.getEventName());
        var secondAuditEvent = capturedAuditEvents.get(1);
        assertEquals(
                AuditEventTypes.IPV_CORE_CRI_RESOURCE_RETRIEVED, secondAuditEvent.getEventName());
    }

    @Test
    void storeCreatedVcsShouldHandleEmptyVcList() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();

        // Act
        criStoringService.storeVcs(
                callbackRequest.getCredentialIssuerId(),
                callbackRequest.getIpAddress(),
                callbackRequest.getIpvSessionId(),
                List.of(),
                clientOAuthSessionItem);

        // Assert
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        var capturedEvent = auditEventCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_CORE_CRI_RESOURCE_RETRIEVED, capturedEvent.getEventName());
    }

    @Test
    void storeCreatedVcsShouldThrowParseExceptionWhenVcCannotBeParsed() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        when(mockSignedJWT.getJWTClaimsSet()).thenThrow(new ParseException("Parse exception!", 0));

        // Act & Assert
        assertThrows(
                ParseException.class,
                () ->
                        criStoringService.storeVcs(
                                callbackRequest.getCredentialIssuerId(),
                                callbackRequest.getIpAddress(),
                                callbackRequest.getIpvSessionId(),
                                List.of(mockSignedJWT),
                                clientOAuthSessionItem));
    }

    @Test
    void storeCreatedVcsShouldThrowCiPutExceptionWhenCiSubmissionFails() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var signedJWT = SignedJWT.parse(M1A_PASSPORT_VC);
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        doThrow(new CiPutException(""))
                .when(mockCiMitService)
                .submitVC(any(SignedJWT.class), any(), any());

        // Act & Assert
        assertThrows(
                CiPutException.class,
                () ->
                        criStoringService.storeVcs(
                                callbackRequest.getCredentialIssuerId(),
                                callbackRequest.getIpAddress(),
                                callbackRequest.getIpvSessionId(),
                                List.of(signedJWT),
                                clientOAuthSessionItem));
    }

    @Test
    void storeCreatedVcsShouldThrowCiPostMitigationsExceptionWhenCiMitigationListSubmissionFails()
            throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var signedJWT = SignedJWT.parse(M1A_PASSPORT_VC);
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
                                callbackRequest.getIpvSessionId(),
                                List.of(signedJWT),
                                clientOAuthSessionItem));
    }

    @Test
    void storeCreatedVcsShouldThrowSqsExceptionWhenAuditEventFailsToSend() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var signedJWT = SignedJWT.parse(M1A_PASSPORT_VC);
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        doThrow(new SqsException("")).when(mockAuditService).sendAuditEvent(any(AuditEvent.class));

        // Act & Assert
        assertThrows(
                SqsException.class,
                () ->
                        criStoringService.storeVcs(
                                callbackRequest.getCredentialIssuerId(),
                                callbackRequest.getIpAddress(),
                                callbackRequest.getIpvSessionId(),
                                List.of(signedJWT),
                                clientOAuthSessionItem));
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
