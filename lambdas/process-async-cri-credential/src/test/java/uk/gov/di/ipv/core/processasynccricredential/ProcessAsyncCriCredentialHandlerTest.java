package uk.gov.di.ipv.core.processasynccricredential;

import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.domain.CriConstants;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;
import uk.gov.di.ipv.core.processasynccricredential.dto.CriResponseMessageDto;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;

@ExtendWith(MockitoExtension.class)
class ProcessAsyncCriCredentialHandlerTest {
    private static final String TEST_MESSAGE_ID = UUID.randomUUID().toString();
    private static final String TEST_CREDENTIAL_ISSUER_ID = CriConstants.F2F_CRI;
    private static final String TEST_USER_ID = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    private static final String TEST_COMPONENT_ID = "f2f";
    private static final String TEST_COMPONENT_ID_ADDRESS = "address";
    private static final String TEST_COMPONENT_ID_CLAIMED_IDENTITY = "claimed_identity";
    private static final String TEST_OAUTH_STATE = UUID.randomUUID().toString();
    private static final String TEST_OAUTH_STATE_2 = UUID.randomUUID().toString();
    private static final CriResponseItem TEST_CRI_RESPONSE_ITEM =
            new CriResponseItem(
                    TEST_USER_ID,
                    TEST_CREDENTIAL_ISSUER_ID,
                    null,
                    TEST_OAUTH_STATE,
                    null,
                    CriResponseService.STATUS_PENDING,
                    0);

    private static final String TEST_ASYNC_ERROR = "access_denied";
    private static final String TEST_ASYNC_ERROR_DESCRIPTION =
            "Additional information on the error";
    private static final OauthCriConfig TEST_CREDENTIAL_ISSUER_CONFIG;
    private static final OauthCriConfig TEST_CREDENTIAL_ISSUER_CONFIG_ADDRESS;
    private static final OauthCriConfig TEST_CREDENTIAL_ISSUER_CONFIG_CLAIMED_IDENTITY;
    private static final VerifiableCredential PASSPORT_VC;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    static {
        try {
            TEST_CREDENTIAL_ISSUER_CONFIG = createOauthCriConfig(TEST_COMPONENT_ID);
            TEST_CREDENTIAL_ISSUER_CONFIG_ADDRESS = createOauthCriConfig(TEST_COMPONENT_ID_ADDRESS);
            TEST_CREDENTIAL_ISSUER_CONFIG_CLAIMED_IDENTITY =
                    createOauthCriConfig(TEST_COMPONENT_ID_CLAIMED_IDENTITY);
            PASSPORT_VC = PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Mock private ConfigService configService;
    @Mock private VerifiableCredentialValidator verifiableCredentialValidator;
    @Mock private VerifiableCredentialService verifiableCredentialService;
    @Mock private AuditService auditService;
    @Mock private CiMitService ciMitService;
    @Mock private CriResponseService criResponseService;
    @InjectMocks private ProcessAsyncCriCredentialHandler handler;

    @Test
    void shouldProcessValidExpectedAsyncVerifiableCredentialSuccessfully() throws Exception {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(verifiableCredentialValidator.parseAndValidate(
                        eq(TEST_USER_ID),
                        eq(TEST_CREDENTIAL_ISSUER_ID),
                        anyList(),
                        any(),
                        any(),
                        any()))
                .thenReturn(List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC));
        when(criResponseService.getCriResponseItem(TEST_USER_ID, TEST_COMPONENT_ID))
                .thenReturn(TEST_CRI_RESPONSE_ITEM);
        mockCredentialIssuerConfig();

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        assertEquals(0, batchResponse.getBatchItemFailures().size());

        verifyVerifiableCredentialJwtValidator();
        verifyCiStorageServicePutContraIndicators();
        verifyVerifiableCredentialService();
        verifyAuditService();
    }

    @Test
    void shouldSendValidExpectedAsyncVerifiableCredentialToCIMITPostMitigationWhenFeatureEnabled()
            throws Exception {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(verifiableCredentialValidator.parseAndValidate(
                        eq(TEST_USER_ID),
                        eq(TEST_CREDENTIAL_ISSUER_ID),
                        anyList(),
                        any(),
                        any(),
                        any()))
                .thenReturn(List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC));
        when(criResponseService.getCriResponseItem(TEST_USER_ID, TEST_COMPONENT_ID))
                .thenReturn(TEST_CRI_RESPONSE_ITEM);
        mockCredentialIssuerConfig();

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        assertEquals(0, batchResponse.getBatchItemFailures().size());

        verifyVerifiableCredentialJwtValidator();
        verifyCiStorageServicePutContraIndicators();
        verifyCiStorageServicePostMitigations();
        verifyVerifiableCredentialService();
        verifyAuditService();
    }

    @Test
    void shouldProcessErrorAsyncVerifiableCredentialSuccessfully()
            throws JsonProcessingException, SqsException {
        final SQSEvent testEvent = createErrorTestEvent();
        when(criResponseService.getCriResponseItem(TEST_USER_ID, TEST_COMPONENT_ID))
                .thenReturn(TEST_CRI_RESPONSE_ITEM);

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verify(criResponseService, times(1)).updateCriResponseItem(TEST_CRI_RESPONSE_ITEM);

        assertEquals(0, batchResponse.getBatchItemFailures().size());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(1, auditEvents.size());
        assertEquals(AuditEventTypes.IPV_F2F_CRI_VC_ERROR, auditEvents.get(0).getEventName());
    }

    @Test
    void shouldRejectValidUnexpectedVerifiableCredential() throws Exception {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE_2);

        when(criResponseService.getCriResponseItem(TEST_USER_ID, TEST_COMPONENT_ID))
                .thenReturn(TEST_CRI_RESPONSE_ITEM);

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verifyVerifiableCredentialNotProcessedFurther();
        verifyBatchResponseFailures(testEvent, batchResponse);
    }

    @Test
    void shouldRejectValidUnsolicitedVerifiableCredential() throws Exception {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(criResponseService.getCriResponseItem(TEST_USER_ID, TEST_COMPONENT_ID))
                .thenReturn(null);

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verifyVerifiableCredentialNotProcessedFurther();

        verifyBatchResponseFailures(testEvent, batchResponse);
    }

    @Test
    void shouldRejectInvalidVerifiableCredential() throws Exception {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(criResponseService.getCriResponseItem(TEST_USER_ID, TEST_COMPONENT_ID))
                .thenReturn(TEST_CRI_RESPONSE_ITEM);
        when(configService.getOauthCriActiveConnectionConfig(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(TEST_CREDENTIAL_ISSUER_CONFIG);
        doThrow(VerifiableCredentialException.class)
                .when(verifiableCredentialValidator)
                .parseAndValidate(any(), any(), anyList(), any(), any(), any());

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verifyVerifiableCredentialNotProcessedFurther();

        verifyBatchResponseFailures(testEvent, batchResponse);
    }

    @Test
    void willNotPersistVerifiableCredentialIfFailsToPutCredentialToCIMIT() throws Exception {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(verifiableCredentialValidator.parseAndValidate(
                        eq(TEST_USER_ID),
                        eq(TEST_CREDENTIAL_ISSUER_ID),
                        anyList(),
                        any(),
                        any(),
                        any()))
                .thenReturn(List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC));
        when(criResponseService.getCriResponseItem(TEST_USER_ID, TEST_COMPONENT_ID))
                .thenReturn(TEST_CRI_RESPONSE_ITEM);
        mockCredentialIssuerConfig();

        doThrow(new CiPutException("Lambda execution failed"))
                .when(ciMitService)
                .submitVC(any(VerifiableCredential.class), eq(null), eq(null));

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verifyVerifiableCredentialJwtValidator();
        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(1, auditEvents.size());
        assertEquals(AuditEventTypes.IPV_F2F_CRI_VC_RECEIVED, auditEvents.get(0).getEventName());

        verify(verifiableCredentialService, never()).persistUserCredentials(any());

        verifyBatchResponseFailures(testEvent, batchResponse);
    }

    @Test
    void willNotPersistVerifiableCredentialIfFailsToPostMitigatingCredentialToCIMIT()
            throws Exception {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(verifiableCredentialValidator.parseAndValidate(
                        eq(TEST_USER_ID),
                        eq(TEST_CREDENTIAL_ISSUER_ID),
                        anyList(),
                        any(),
                        any(),
                        any()))
                .thenReturn(List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC));
        when(criResponseService.getCriResponseItem(TEST_USER_ID, TEST_COMPONENT_ID))
                .thenReturn(TEST_CRI_RESPONSE_ITEM);
        mockCredentialIssuerConfig();

        doThrow(new CiPostMitigationsException("Lambda execution failed"))
                .when(ciMitService)
                .submitMitigatingVcList(anyList(), eq(null), eq(null));

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verifyVerifiableCredentialJwtValidator();
        verify(auditService, times(1))
                .sendAuditEvent(ArgumentCaptor.forClass(AuditEvent.class).capture());
        verify(ciMitService, times(1)).submitVC(any(), any(), any());
        verify(verifiableCredentialService, never()).persistUserCredentials(any());

        verifyBatchResponseFailures(testEvent, batchResponse);
    }

    private SQSEvent createErrorTestEvent() throws JsonProcessingException {
        final SQSEvent sqsEvent = new SQSEvent();
        final CriResponseMessageDto criResponseMessageDto =
                new CriResponseMessageDto(
                        null,
                        TEST_USER_ID,
                        TEST_OAUTH_STATE,
                        null,
                        TEST_ASYNC_ERROR,
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
                        null,
                        TEST_USER_ID,
                        testOauthState,
                        List.of(PASSPORT_VC.getVcString()),
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
                .parseAndValidate(any(), any(), anyList(), any(), any(), any());
    }

    private void verifyAuditService() throws SqsException {
        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(2, auditEvents.size());
        assertEquals(AuditEventTypes.IPV_F2F_CRI_VC_RECEIVED, auditEvents.get(0).getEventName());
        assertEquals(AuditEventTypes.IPV_F2F_CRI_VC_CONSUMED, auditEvents.get(1).getEventName());
    }

    private void verifyCiStorageServicePutContraIndicators() throws Exception {
        var ciVcCaptor = ArgumentCaptor.forClass(VerifiableCredential.class);
        var govukSigninJourneyIdCaptor = ArgumentCaptor.forClass(String.class);
        var ipAddressCaptor = ArgumentCaptor.forClass(String.class);
        verify(ciMitService, times(1))
                .submitVC(
                        ciVcCaptor.capture(),
                        govukSigninJourneyIdCaptor.capture(),
                        ipAddressCaptor.capture());

        var ciVcs = ciVcCaptor.getAllValues();
        assertEquals(1, ciVcs.size());
        assertEquals(PASSPORT_VC, ciVcs.get(0));

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

        verify(ciMitService, times(1))
                .submitMitigatingVcList(
                        postedVcsCaptor.capture(),
                        govukSigninJourneyIdCaptor.capture(),
                        ipAddressCaptor.capture());

        var postedVcs = postedVcsCaptor.getValue();
        assertEquals(1, postedVcs.size());
        assertEquals(PASSPORT_VC, postedVcs.get(0));

        var ciJourneyIds = govukSigninJourneyIdCaptor.getAllValues();
        assertEquals(1, ciJourneyIds.size());
        assertNull(ciJourneyIds.get(0));

        var ciIpAddresses = ipAddressCaptor.getAllValues();
        assertEquals(1, ciIpAddresses.size());
        assertNull(ciIpAddresses.get(0));
    }

    private void verifyVerifiableCredentialService() throws Exception {
        var vcCaptor = ArgumentCaptor.forClass(VerifiableCredential.class);

        verify(verifiableCredentialService, times(1)).persistUserCredentials(vcCaptor.capture());

        var storedVcs = vcCaptor.getAllValues();
        assertEquals(1, storedVcs.size());
        assertEquals(PASSPORT_VC, storedVcs.get(0));
    }

    private void verifyVerifiableCredentialNotProcessedFurther() throws Exception {
        verify(auditService, never())
                .sendAuditEvent(ArgumentCaptor.forClass(AuditEvent.class).capture());
        verify(verifiableCredentialService, never()).persistUserCredentials(any());
        verify(ciMitService, never()).submitVC(any(), any(), any());
        verify(ciMitService, never()).submitMitigatingVcList(any(), any(), any());
    }

    private static void verifyBatchResponseFailures(
            SQSEvent testEvent, SQSBatchResponse batchResponse) {
        assertEquals(1, batchResponse.getBatchItemFailures().size());
        assertEquals(
                testEvent.getRecords().get(0).getMessageId(),
                batchResponse.getBatchItemFailures().get(0).getItemIdentifier());
    }

    private void mockCredentialIssuerConfig() {
        when(configService.getOauthCriActiveConnectionConfig(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(TEST_CREDENTIAL_ISSUER_CONFIG);
        when(configService.getComponentId(ADDRESS_CRI))
                .thenReturn(TEST_CREDENTIAL_ISSUER_CONFIG_ADDRESS.getComponentId());
        when(configService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(TEST_CREDENTIAL_ISSUER_CONFIG_CLAIMED_IDENTITY.getComponentId());
    }

    private static OauthCriConfig createOauthCriConfig(String componentId)
            throws URISyntaxException {
        return OauthCriConfig.builder()
                .tokenUrl(new URI(""))
                .credentialUrl(new URI(""))
                .authorizeUrl(new URI(""))
                .clientId("ipv-core")
                .signingKey(EC_PRIVATE_KEY_JWK)
                .encryptionKey(null)
                .componentId(componentId)
                .clientCallbackUrl(new URI(""))
                .requiresApiKey(false)
                .requiresAdditionalEvidence(false)
                .build();
    }
}
