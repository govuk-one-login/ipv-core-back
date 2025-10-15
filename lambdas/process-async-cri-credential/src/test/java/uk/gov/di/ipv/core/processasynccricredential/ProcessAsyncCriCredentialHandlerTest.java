package uk.gov.di.ipv.core.processasynccricredential;

import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
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
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;
import uk.gov.di.ipv.core.processasynccricredential.dto.CriResponseMessageDto;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fPassportPhotoM1a;

@ExtendWith(MockitoExtension.class)
class ProcessAsyncCriCredentialHandlerTest {
    private static final String TEST_MESSAGE_ID = UUID.randomUUID().toString();
    private static final String TEST_CREDENTIAL_ISSUER_ID = F2F.getId();
    private static final String TEST_USER_ID = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final Cri TEST_CRI = Cri.F2F;
    private static final String TEST_COMPONENT_ID = TEST_CRI.getId();
    private static final String TEST_OAUTH_STATE = UUID.randomUUID().toString();
    private static final CriResponseItem TEST_CRI_RESPONSE_ITEM =
            new CriResponseItem(
                    TEST_USER_ID,
                    TEST_CREDENTIAL_ISSUER_ID,
                    null,
                    TEST_OAUTH_STATE,
                    null,
                    CriResponseService.STATUS_PENDING,
                    0,
                    List.of(),
                    false);

    private static final String TEST_ASYNC_ACCESS_DENIED_ERROR = "access_denied";
    private static final String TEST_ASYNC_ERROR = "invalid";

    private static final String TEST_ASYNC_ERROR_DESCRIPTION =
            "Additional information on the error";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static OauthCriConfig TEST_CREDENTIAL_ISSUER_CONFIG;
    private VerifiableCredential F2F_VC;

    @Captor private ArgumentCaptor<VerifiableCredential> vcArgumentCaptor;
    @Mock private ConfigService configService;
    @Mock private Config mockConfig;
    @Mock private VerifiableCredentialValidator verifiableCredentialValidator;
    @Mock private AuditService auditService;
    @Mock private CimitService cimitService;
    @Mock private CriResponseService criResponseService;
    @Mock private EvcsService evcsService;
    @InjectMocks private ProcessAsyncCriCredentialHandler handler;

    @BeforeAll
    static void setUpBeforeAll() throws URISyntaxException {
        TEST_CREDENTIAL_ISSUER_CONFIG = createTestOauthCriConfig();
    }

    @BeforeEach
    void setUp() {
        F2F_VC = vcF2fPassportPhotoM1a();
        when(configService.getComponentId()).thenReturn("https://core-component.example");
    }

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(auditService);
        auditInOrder.verify(auditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

    @Test
    void shouldProcessValidExpectedAsyncVerifiableCredentialSuccessfully() throws Exception {
        when(verifiableCredentialValidator.parseAndValidate(
                        eq(TEST_USER_ID), eq(F2F), anyList(), any(), any()))
                .thenReturn(List.of(F2F_VC));
        when(criResponseService.getCriResponseItemWithState(TEST_USER_ID, TEST_OAUTH_STATE))
                .thenReturn(Optional.of(TEST_CRI_RESPONSE_ITEM));
        mockCredentialIssuerConfig();

        var batchResponse = handler.handleRequest(createSuccessTestEvent(TEST_OAUTH_STATE), null);

        assertEquals(0, batchResponse.getBatchItemFailures().size());

        verifyVerifiableCredentialJwtValidator();
        verifyCiStorageServicePutContraIndicators();
        verifyCiStorageServicePostMitigations();
        verifyVerifiableCredentialService();
        verify(evcsService).storePendingVc(F2F_VC);
        verifyAuditService();
    }

    @Test
    void shouldProcessErrorAsyncVerifiableCredentialSuccessfully() throws JsonProcessingException {
        final SQSEvent testEvent = createErrorTestEvent(TEST_ASYNC_ERROR);
        when(criResponseService.getCriResponseItemWithState(TEST_USER_ID, TEST_OAUTH_STATE))
                .thenReturn(Optional.of(TEST_CRI_RESPONSE_ITEM));

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verify(criResponseService, times(1)).updateCriResponseItem(TEST_CRI_RESPONSE_ITEM);

        assertEquals(0, batchResponse.getBatchItemFailures().size());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(2, auditEvents.size());
        assertEquals(AuditEventTypes.IPV_F2F_CRI_VC_ERROR, auditEvents.get(0).getEventName());
        assertEquals(AuditEventTypes.IPV_ASYNC_CRI_VC_ERROR, auditEvents.get(1).getEventName());
        assertEquals(CriResponseService.STATUS_ERROR, TEST_CRI_RESPONSE_ITEM.getStatus());
    }

    @Test
    void shouldProcessAccessDeniedErrorAsyncVerifiableCredentialSuccessfully()
            throws JsonProcessingException {
        final SQSEvent testEvent = createErrorTestEvent(TEST_ASYNC_ACCESS_DENIED_ERROR);
        when(criResponseService.getCriResponseItemWithState(TEST_USER_ID, TEST_OAUTH_STATE))
                .thenReturn(Optional.of(TEST_CRI_RESPONSE_ITEM));

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verify(criResponseService, times(1)).updateCriResponseItem(TEST_CRI_RESPONSE_ITEM);

        assertEquals(0, batchResponse.getBatchItemFailures().size());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(2, auditEvents.size());
        assertEquals(AuditEventTypes.IPV_F2F_CRI_VC_ERROR, auditEvents.get(0).getEventName());
        assertEquals(AuditEventTypes.IPV_ASYNC_CRI_VC_ERROR, auditEvents.get(1).getEventName());
        assertEquals(CriResponseService.STATUS_ABANDON, TEST_CRI_RESPONSE_ITEM.getStatus());
    }

    @Test
    void shouldDiscardValidUnsolicitedVerifiableCredentialWithoutRetry() throws Exception {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(criResponseService.getCriResponseItemWithState(TEST_USER_ID, TEST_OAUTH_STATE))
                .thenReturn(Optional.empty());

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verifyVerifiableCredentialNotProcessedFurther();

        assertEquals(0, batchResponse.getBatchItemFailures().size());
    }

    @Test
    void shouldRejectInvalidVerifiableCredential() throws Exception {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(criResponseService.getCriResponseItemWithState(TEST_USER_ID, TEST_OAUTH_STATE))
                .thenReturn(Optional.of(TEST_CRI_RESPONSE_ITEM));
        when(configService.getOauthCriActiveConnectionConfig(F2F))
                .thenReturn(TEST_CREDENTIAL_ISSUER_CONFIG);
        doThrow(VerifiableCredentialException.class)
                .when(verifiableCredentialValidator)
                .parseAndValidate(any(), any(), anyList(), any(), any());

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verifyVerifiableCredentialNotProcessedFurther();

        verifyBatchResponseFailures(testEvent, batchResponse);
    }

    @Test
    void willNotPersistVerifiableCredentialIfFailsToPutCredentialToCIMIT() throws Exception {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(verifiableCredentialValidator.parseAndValidate(
                        eq(TEST_USER_ID), eq(F2F), anyList(), any(), any()))
                .thenReturn(List.of(F2F_VC));
        when(criResponseService.getCriResponseItemWithState(TEST_USER_ID, TEST_OAUTH_STATE))
                .thenReturn(Optional.of(TEST_CRI_RESPONSE_ITEM));
        mockCredentialIssuerConfig();

        doThrow(new CiPutException("Lambda execution failed"))
                .when(cimitService)
                .submitVC(any(VerifiableCredential.class), eq(null), eq(null));

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verifyVerifiableCredentialJwtValidator();
        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(2, auditEvents.size());
        assertEquals(AuditEventTypes.IPV_F2F_CRI_VC_RECEIVED, auditEvents.get(0).getEventName());
        assertEquals(AuditEventTypes.IPV_ASYNC_CRI_VC_RECEIVED, auditEvents.get(1).getEventName());

        verify(evcsService, never()).storePendingVc(any());

        verifyBatchResponseFailures(testEvent, batchResponse);
    }

    @Test
    void willNotPersistVerifiableCredentialIfFailsToPostMitigatingCredentialToCIMIT()
            throws Exception {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(verifiableCredentialValidator.parseAndValidate(
                        eq(TEST_USER_ID), eq(F2F), anyList(), any(), any()))
                .thenReturn(List.of(F2F_VC));
        when(criResponseService.getCriResponseItemWithState(TEST_USER_ID, TEST_OAUTH_STATE))
                .thenReturn(Optional.of(TEST_CRI_RESPONSE_ITEM));
        mockCredentialIssuerConfig();

        doThrow(new CiPostMitigationsException("Lambda execution failed"))
                .when(cimitService)
                .submitMitigatingVcList(anyList(), eq(null), eq(null));

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verifyVerifiableCredentialJwtValidator();
        verify(auditService, times(2))
                .sendAuditEvent(ArgumentCaptor.forClass(AuditEvent.class).capture());
        verify(cimitService, times(1)).submitVC(any(), any(), any());
        verify(evcsService, never()).storePendingVc(any());

        verifyBatchResponseFailures(testEvent, batchResponse);
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(criResponseService.getCriResponseItemWithState(any(), any()))
                .thenThrow(new RuntimeException("Test error"));

        var logCollector = LogCollector.getLogCollectorFor(ProcessAsyncCriCredentialHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> handler.handleRequest(testEvent, null),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        Optional<String> logMessage =
                logCollector.getLogMessages().stream()
                        .filter(msg -> msg.contains("Unhandled lambda exception"))
                        .findFirst();
        assertTrue(logMessage.isPresent());
        assertThat(logMessage.get(), containsString("Test error"));
    }

    private SQSEvent createErrorTestEvent(String errorType) throws JsonProcessingException {
        final SQSEvent sqsEvent = new SQSEvent();
        final CriResponseMessageDto criResponseMessageDto =
                new CriResponseMessageDto(
                        TEST_USER_ID,
                        TEST_OAUTH_STATE,
                        TEST_JOURNEY_ID,
                        null,
                        errorType,
                        TEST_ASYNC_ERROR_DESCRIPTION);
        final SQSEvent.SQSMessage message = new SQSEvent.SQSMessage();
        message.setMessageId(TEST_MESSAGE_ID);
        message.setBody(OBJECT_MAPPER.writeValueAsString(criResponseMessageDto));
        sqsEvent.setRecords(List.of(message));
        return sqsEvent;
    }

    private SQSEvent createSuccessTestEvent(String testOauthState) throws Exception {
        final SQSEvent sqsEvent = new SQSEvent();
        final CriResponseMessageDto criResponseMessageDto =
                new CriResponseMessageDto(
                        TEST_USER_ID,
                        testOauthState,
                        TEST_JOURNEY_ID,
                        List.of(F2F_VC.getVcString()),
                        null,
                        null);
        final SQSEvent.SQSMessage message = new SQSEvent.SQSMessage();
        message.setMessageId(TEST_MESSAGE_ID);
        message.setBody(OBJECT_MAPPER.writeValueAsString(criResponseMessageDto));
        sqsEvent.setRecords(List.of(message));
        return sqsEvent;
    }

    private void verifyVerifiableCredentialJwtValidator() throws Exception {
        verify(verifiableCredentialValidator)
                .parseAndValidate(any(), any(), anyList(), any(), any());
    }

    private void verifyAuditService() {
        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(4)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(4, auditEvents.size());
        assertEquals(AuditEventTypes.IPV_F2F_CRI_VC_RECEIVED, auditEvents.get(0).getEventName());
        assertEquals(AuditEventTypes.IPV_ASYNC_CRI_VC_RECEIVED, auditEvents.get(1).getEventName());
        assertEquals(AuditEventTypes.IPV_F2F_CRI_VC_CONSUMED, auditEvents.get(2).getEventName());
        assertEquals(AuditEventTypes.IPV_ASYNC_CRI_VC_CONSUMED, auditEvents.get(3).getEventName());
    }

    private void verifyCiStorageServicePutContraIndicators() throws Exception {
        var ciVcCaptor = ArgumentCaptor.forClass(VerifiableCredential.class);
        var govukSigninJourneyIdCaptor = ArgumentCaptor.forClass(String.class);
        var ipAddressCaptor = ArgumentCaptor.forClass(String.class);
        verify(cimitService, times(1))
                .submitVC(
                        ciVcCaptor.capture(),
                        govukSigninJourneyIdCaptor.capture(),
                        ipAddressCaptor.capture());

        var ciVcs = ciVcCaptor.getAllValues();
        assertEquals(1, ciVcs.size());
        assertEquals(F2F_VC, ciVcs.get(0));

        var ciJourneyIds = govukSigninJourneyIdCaptor.getAllValues();
        assertEquals(1, ciJourneyIds.size());
        assertNull(ciJourneyIds.get(0));

        var ciIpAddresses = ipAddressCaptor.getAllValues();
        assertEquals(1, ciIpAddresses.size());
        assertNull(ciIpAddresses.get(0));
    }

    private void verifyCiStorageServicePostMitigations() throws Exception {
        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<VerifiableCredential>> postedVcsCaptor =
                ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<String> govukSigninJourneyIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> ipAddressCaptor = ArgumentCaptor.forClass(String.class);

        verify(cimitService, times(1))
                .submitMitigatingVcList(
                        postedVcsCaptor.capture(),
                        govukSigninJourneyIdCaptor.capture(),
                        ipAddressCaptor.capture());

        var postedVcs = postedVcsCaptor.getValue();
        assertEquals(1, postedVcs.size());
        assertEquals(F2F_VC, postedVcs.get(0));

        var ciJourneyIds = govukSigninJourneyIdCaptor.getAllValues();
        assertEquals(1, ciJourneyIds.size());
        assertNull(ciJourneyIds.get(0));

        var ciIpAddresses = ipAddressCaptor.getAllValues();
        assertEquals(1, ciIpAddresses.size());
        assertNull(ciIpAddresses.get(0));
    }

    private void verifyVerifiableCredentialService() throws Exception {
        verify(evcsService).storePendingVc(vcArgumentCaptor.capture());

        var storedVcs = vcArgumentCaptor.getAllValues();
        assertEquals(1, storedVcs.size());
        assertEquals(F2F_VC, storedVcs.get(0));
    }

    private void verifyVerifiableCredentialNotProcessedFurther() throws Exception {
        verify(auditService, never())
                .sendAuditEvent(ArgumentCaptor.forClass(AuditEvent.class).capture());
        verify(evcsService, never()).storePendingVc(any());
        verify(cimitService, never()).submitVC(any(), any(), any());
        verify(cimitService, never()).submitMitigatingVcList(any(), any(), any());
    }

    private static void verifyBatchResponseFailures(
            SQSEvent testEvent, SQSBatchResponse batchResponse) {
        assertEquals(1, batchResponse.getBatchItemFailures().size());
        assertEquals(
                testEvent.getRecords().get(0).getMessageId(),
                batchResponse.getBatchItemFailures().get(0).getItemIdentifier());
    }

    private void mockCredentialIssuerConfig() {
        when(configService.getOauthCriActiveConnectionConfig(F2F))
                .thenReturn(TEST_CREDENTIAL_ISSUER_CONFIG);
    }

    private static OauthCriConfig createTestOauthCriConfig() throws URISyntaxException {
        return OauthCriConfig.builder()
                .tokenUrl(new URI(""))
                .credentialUrl(new URI(""))
                .authorizeUrl(new URI(""))
                .clientId("ipv-core")
                .signingKey(EC_PRIVATE_KEY_JWK)
                .componentId(TEST_COMPONENT_ID)
                .clientCallbackUrl(new URI(""))
                .requiresApiKey(false)
                .requiresAdditionalEvidence(false)
                .build();
    }
}
