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
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.ScopeConstants;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.testhelpers.unit.ConfigServiceHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.dto.VerifiableCredentialResponseDto;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.DWP_KBV;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDwpKbv;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcTicf;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;

@ExtendWith(MockitoExtension.class)
class CriStoringServiceTest {
    private static final String TEST_AUTHORISATION_CODE = "test_authorisation_code";
    private static final String TEST_IPV_SESSION_ID = "test_ipv_Session_id";
    private static final String TEST_CRI_OAUTH_SESSION_ID = "test_cri_oauth_session_id";
    private static final String TEST_USER_ID = "test_user_id";
    @Mock private ConfigService mockConfigService;
    @Mock private Config mockConfig;
    @Mock private AuditService mockAuditService;
    @Mock private CriResponseService mockCriResponseService;
    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @Mock private CimitService mockCimitService;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @InjectMocks private CriStoringService criStoringService;
    @Captor private ArgumentCaptor<ClientOAuthSessionItem> clientSessionItemCaptor;
    @Captor private ArgumentCaptor<Cri> criCaptor;
    @Captor private ArgumentCaptor<String> vcResponseCaptor;
    @Captor private ArgumentCaptor<String> criOAuthSessionIdCaptor;
    @Captor private ArgumentCaptor<AuditEvent> auditEventCaptor;
    @Captor private ArgumentCaptor<VerifiableCredential> vcCaptor;
    @Captor private ArgumentCaptor<List<VerifiableCredential>> vcListCaptor;

    @BeforeEach
    void setup() {
        ConfigServiceHelper.stubDefaultComponentIdConfig(mockConfigService, mockConfig);
    }

    @Test
    void storeCriResponseShouldStoreResponseAndSendAuditEvent() throws JsonProcessingException {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();

        // Act
        criStoringService.recordCriResponse(callbackRequest, clientOAuthSessionItem);

        verifyAndAssert(callbackRequest.getFeatureSet(), clientOAuthSessionItem);
    }

    @Test
    void storeCriResponseShouldStoreResponseAndSendAuditEvent_forJourneyReq()
            throws JsonProcessingException {
        // Arrange
        var journeyRequest = new JourneyRequest();
        journeyRequest.setIpvSessionId(TEST_IPV_SESSION_ID);
        journeyRequest.setIpAddress("testAdd");
        journeyRequest.setDeviceInformation("testDeviceInfo");
        var featureSets = List.of("eWrite", "eRead");
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();

        // Act
        criStoringService.recordCriResponse(
                journeyRequest,
                F2F,
                TEST_CRI_OAUTH_SESSION_ID,
                clientOAuthSessionItem,
                featureSets);

        verifyAndAssert(featureSets, clientOAuthSessionItem);
    }

    private void verifyAndAssert(
            List<String> featureSets, ClientOAuthSessionItem clientOAuthSessionItem)
            throws JsonProcessingException {
        // verify
        verify(mockCriResponseService)
                .persistCriResponse(
                        clientSessionItemCaptor.capture(),
                        criCaptor.capture(),
                        vcResponseCaptor.capture(),
                        criOAuthSessionIdCaptor.capture(),
                        eq(CriResponseService.STATUS_PENDING),
                        eq(featureSets));

        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());

        // Assert

        assertEquals(F2F, criCaptor.getValue());
        assertEquals(TEST_CRI_OAUTH_SESSION_ID, criOAuthSessionIdCaptor.getValue());

        assertEquals(
                clientOAuthSessionItem.getUserId(), clientSessionItemCaptor.getValue().getUserId());
        assertEquals(Boolean.TRUE, clientSessionItemCaptor.getValue().getReproveIdentity());
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
    void storeVcsShouldProcessVcsAndSendAuditEvents() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest(DWP_KBV);
        var vc = vcDwpKbv();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        var addressVc = vcAddressM1a();
        var sessionVcs = List.of(addressVc);

        // Act
        criStoringService.storeVcs(
                callbackRequest.getCredentialIssuer(),
                callbackRequest.getIpAddress(),
                callbackRequest.getDeviceInformation(),
                List.of(vc),
                clientOAuthSessionItem,
                mockIpvSessionItem,
                sessionVcs);

        // Assert
        verify(mockCimitService)
                .submitVC(
                        vcCaptor.capture(),
                        eq(clientOAuthSessionItem.getGovukSigninJourneyId()),
                        eq(callbackRequest.getIpAddress()));
        assertEquals(vc, vcCaptor.getValue());

        verify(mockCimitService)
                .submitMitigatingVcList(
                        vcListCaptor.capture(),
                        eq(clientOAuthSessionItem.getGovukSigninJourneyId()),
                        eq(callbackRequest.getIpAddress()));
        assertEquals(List.of(addressVc, vc), vcListCaptor.getValue());

        assertEquals(vc, vcCaptor.getValue());

        verify(mockAuditService, times(3)).sendAuditEvent(auditEventCaptor.capture());
        var capturedAuditEvents = auditEventCaptor.getAllValues();
        assertEquals(
                AuditEventTypes.IPV_DWP_KBV_CRI_VC_ISSUED,
                capturedAuditEvents.get(0).getEventName());
        assertEquals(AuditEventTypes.IPV_VC_RECEIVED, capturedAuditEvents.get(1).getEventName());
        assertEquals(
                AuditEventTypes.IPV_CORE_CRI_RESOURCE_RETRIEVED,
                capturedAuditEvents.get(2).getEventName());

        verify(mockSessionCredentialsService, never()).deleteSessionCredentialsForCri(any(), any());
        verify(mockSessionCredentialsService)
                .persistCredentials(List.of(vc), mockIpvSessionItem.getIpvSessionId(), true);
        verify(mockIpvSessionItem, times(0)).setRiskAssessmentCredential(vc.getVcString());
    }

    @Test
    void storeVcsShouldNotSubmitVcsToCimitServiceWhenOnReverificationJourney() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        clientOAuthSessionItem.setScope(ScopeConstants.REVERIFICATION);

        // Act
        criStoringService.storeVcs(
                callbackRequest.getCredentialIssuer(),
                callbackRequest.getIpAddress(),
                callbackRequest.getDeviceInformation(),
                List.of(vcWebPassportSuccessful()),
                clientOAuthSessionItem,
                mockIpvSessionItem,
                List.of());

        // Assert
        verify(mockCimitService, never()).submitVC(any(), any(), any());
        verify(mockCimitService, never()).submitMitigatingVcList(any(), any(), any());
    }

    @Test
    void storeVcsShouldRemoveExistingAddressVcFromSessionCredentialsStoreIfNewAddressVcReceived()
            throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var vc = vcAddressOne();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();

        // Act
        criStoringService.storeVcs(
                ADDRESS,
                callbackRequest.getIpAddress(),
                callbackRequest.getDeviceInformation(),
                List.of(vc),
                clientOAuthSessionItem,
                mockIpvSessionItem,
                List.of());

        // Assert
        verify(mockSessionCredentialsService)
                .deleteSessionCredentialsForCri(mockIpvSessionItem.getIpvSessionId(), ADDRESS);
        verify(mockSessionCredentialsService)
                .persistCredentials(List.of(vc), mockIpvSessionItem.getIpvSessionId(), true);
        verify(mockIpvSessionItem, times(0)).setRiskAssessmentCredential(vc.getVcString());
    }

    @Test
    void storeVcsShouldProcessTicfVcsAndSendAuditEvents() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var vc = vcTicf();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();

        // Act
        criStoringService.storeVcs(
                TICF,
                callbackRequest.getIpAddress(),
                callbackRequest.getDeviceInformation(),
                List.of(vc),
                clientOAuthSessionItem,
                mockIpvSessionItem,
                List.of());

        // Assert
        verify(mockCimitService)
                .submitVC(
                        vcCaptor.capture(),
                        eq(clientOAuthSessionItem.getGovukSigninJourneyId()),
                        eq(callbackRequest.getIpAddress()));
        assertEquals(vc, vcCaptor.getValue());

        verify(mockCimitService)
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

        verify(mockSessionCredentialsService, never())
                .persistCredentials(List.of(vc), mockIpvSessionItem.getIpvSessionId(), true);
        verify(mockIpvSessionItem).setRiskAssessmentCredential(vc.getVcString());
    }

    @Test
    void storeVcsShouldHandleEmptyVcList() throws Exception {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();

        // Act
        criStoringService.storeVcs(
                callbackRequest.getCredentialIssuer(),
                callbackRequest.getIpAddress(),
                callbackRequest.getDeviceInformation(),
                List.of(),
                clientOAuthSessionItem,
                mockIpvSessionItem,
                List.of());

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
                .when(mockCimitService)
                .submitVC(any(VerifiableCredential.class), any(), any());

        // Act & Assert
        assertThrows(
                CiPutException.class,
                () ->
                        criStoringService.storeVcs(
                                callbackRequest.getCredentialIssuer(),
                                callbackRequest.getIpAddress(),
                                callbackRequest.getDeviceInformation(),
                                List.of(vcWebPassportSuccessful()),
                                clientOAuthSessionItem,
                                mockIpvSessionItem,
                                List.of()));
    }

    @Test
    void storeVcsShouldThrowCiPostMitigationsExceptionWhenCiMitigationListSubmissionFails()
            throws CiPostMitigationsException {
        // Arrange
        var callbackRequest = buildValidCallbackRequest();
        var clientOAuthSessionItem = buildValidClientOAuthSessionItem();
        doThrow(new CiPostMitigationsException(""))
                .when(mockCimitService)
                .submitMitigatingVcList(any(), any(), any());

        // Act & Assert
        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        criStoringService.storeVcs(
                                callbackRequest.getCredentialIssuer(),
                                callbackRequest.getIpAddress(),
                                callbackRequest.getDeviceInformation(),
                                List.of(vcWebPassportSuccessful()),
                                clientOAuthSessionItem,
                                mockIpvSessionItem,
                                List.of()));
    }

    private CriCallbackRequest buildValidCallbackRequest() {
        return buildValidCallbackRequest(F2F);
    }

    private CriCallbackRequest buildValidCallbackRequest(Cri credentialIssuer) {
        return CriCallbackRequest.builder()
                .ipvSessionId(TEST_IPV_SESSION_ID)
                .credentialIssuerId(credentialIssuer.getId())
                .authorizationCode(TEST_AUTHORISATION_CODE)
                .state(TEST_CRI_OAUTH_SESSION_ID)
                .build();
    }

    private ClientOAuthSessionItem buildValidClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder()
                .userId(TEST_USER_ID)
                .scope(ScopeConstants.OPENID)
                .reproveIdentity(Boolean.TRUE)
                .build();
    }
}
