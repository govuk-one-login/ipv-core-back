package uk.gov.di.ipv.core.processasynccricredential;

import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
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
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;
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
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

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
    private static final CredentialIssuerConfig TEST_CREDENTIAL_ISSUER_CONFIG;
    private static final CredentialIssuerConfig TEST_CREDENTIAL_ISSUER_CONFIG_ADDRESS;
    private static final CredentialIssuerConfig TEST_CREDENTIAL_ISSUER_CONFIG_CLAIMED_IDENTITY;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    static {
        try {
            TEST_CREDENTIAL_ISSUER_CONFIG =
                    new CredentialIssuerConfig(
                            new URI(""),
                            new URI(""),
                            new URI(""),
                            "ipv-core",
                            EC_PRIVATE_KEY_JWK,
                            null,
                            TEST_COMPONENT_ID,
                            new URI(""),
                            false);
            TEST_CREDENTIAL_ISSUER_CONFIG_ADDRESS =
                    new CredentialIssuerConfig(
                            new URI(""),
                            new URI(""),
                            new URI(""),
                            "ipv-core",
                            EC_PRIVATE_KEY_JWK,
                            null,
                            TEST_COMPONENT_ID_ADDRESS,
                            new URI(""),
                            false);
            TEST_CREDENTIAL_ISSUER_CONFIG_CLAIMED_IDENTITY =
                    new CredentialIssuerConfig(
                            new URI(""),
                            new URI(""),
                            new URI(""),
                            "ipv-core",
                            EC_PRIVATE_KEY_JWK,
                            null,
                            TEST_COMPONENT_ID_CLAIMED_IDENTITY,
                            new URI(""),
                            false);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    @Mock private ConfigService configService;
    @Mock private VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    @Mock private VerifiableCredentialService verifiableCredentialService;
    @Mock private AuditService auditService;
    @Mock private CiMitService ciMitService;
    @Mock private CriResponseService criResponseService;

    @InjectMocks private ProcessAsyncCriCredentialHandler handler;

    @Test
    void shouldProcessValidExpectedAsyncVerifiableCredentialSuccessfully()
            throws JsonProcessingException, SqsException, CiPutException {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

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
            throws JsonProcessingException, SqsException, CiPutException,
                    CiPostMitigationsException {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

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
    void shouldRejectValidUnexpectedVerifiableCredential()
            throws JsonProcessingException, CiPostMitigationsException, CiPutException,
                    SqsException {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE_2);

        when(criResponseService.getCriResponseItem(TEST_USER_ID, TEST_COMPONENT_ID))
                .thenReturn(TEST_CRI_RESPONSE_ITEM);

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verifyVerifiableCredentialNotProcessedFurther();
        verifyBatchResponseFailures(testEvent, batchResponse);
    }

    @Test
    void shouldRejectValidUnsolicitedVerifiableCredential()
            throws JsonProcessingException, CiPostMitigationsException, CiPutException,
                    SqsException {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(criResponseService.getCriResponseItem(TEST_USER_ID, TEST_COMPONENT_ID))
                .thenReturn(null);

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verifyVerifiableCredentialNotProcessedFurther();

        verifyBatchResponseFailures(testEvent, batchResponse);
    }

    @Test
    void shouldRejectInvalidVerifiableCredential()
            throws JsonProcessingException, CiPutException, CiPostMitigationsException,
                    SqsException {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(criResponseService.getCriResponseItem(TEST_USER_ID, TEST_COMPONENT_ID))
                .thenReturn(TEST_CRI_RESPONSE_ITEM);
        when(configService.getCredentialIssuerActiveConnectionConfig(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(TEST_CREDENTIAL_ISSUER_CONFIG);
        doThrow(VerifiableCredentialException.class)
                .when(verifiableCredentialJwtValidator)
                .validate(any(), any(), any());

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verifyVerifiableCredentialNotProcessedFurther();

        verifyBatchResponseFailures(testEvent, batchResponse);
    }

    @Test
    void willNotPersistVerifiableCredentialIfFailsToPutCredentialToCIMIT()
            throws JsonProcessingException, CiPutException, SqsException {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

        when(criResponseService.getCriResponseItem(TEST_USER_ID, TEST_COMPONENT_ID))
                .thenReturn(TEST_CRI_RESPONSE_ITEM);
        mockCredentialIssuerConfig();

        doThrow(new CiPutException("Lambda execution failed"))
                .when(ciMitService)
                .submitVC(any(SignedJWT.class), eq(null), eq(null));

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);

        verifyVerifiableCredentialJwtValidator();
        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(1, auditEvents.size());
        assertEquals(AuditEventTypes.IPV_F2F_CRI_VC_RECEIVED, auditEvents.get(0).getEventName());

        verify(verifiableCredentialService, never()).persistUserCredentials(any(), any(), any());

        verifyBatchResponseFailures(testEvent, batchResponse);
    }

    @Test
    void willNotPersistVerifiableCredentialIfFailsToPostMitigatingCredentialToCIMIT()
            throws JsonProcessingException, CiPostMitigationsException, SqsException,
                    CiPutException {
        final SQSEvent testEvent = createSuccessTestEvent(TEST_OAUTH_STATE);

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
        verify(verifiableCredentialService, never()).persistUserCredentials(any(), any(), any());

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

    private SQSEvent createSuccessTestEvent(String testOauthState) throws JsonProcessingException {
        final SQSEvent sqsEvent = new SQSEvent();
        final CriResponseMessageDto criResponseMessageDto =
                new CriResponseMessageDto(
                        null,
                        TEST_USER_ID,
                        testOauthState,
                        List.of(TestFixtures.SIGNED_VC_1),
                        null,
                        null);
        final SQSEvent.SQSMessage message = new SQSEvent.SQSMessage();
        message.setMessageId(TEST_MESSAGE_ID);
        message.setBody(OBJECT_MAPPER.writeValueAsString(criResponseMessageDto));
        sqsEvent.setRecords(List.of(message));
        return sqsEvent;
    }

    private void verifyVerifiableCredentialJwtValidator() {
        verify(verifiableCredentialJwtValidator)
                .validate(
                        any(SignedJWT.class), eq(TEST_CREDENTIAL_ISSUER_CONFIG), eq(TEST_USER_ID));
    }

    private void verifyAuditService() throws SqsException {
        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(2, auditEvents.size());
        assertEquals(AuditEventTypes.IPV_F2F_CRI_VC_RECEIVED, auditEvents.get(0).getEventName());
        assertEquals(AuditEventTypes.IPV_F2F_CRI_VC_CONSUMED, auditEvents.get(1).getEventName());
    }

    private void verifyCiStorageServicePutContraIndicators() throws CiPutException {
        ArgumentCaptor<SignedJWT> ciVerifiableCredentialCaptor =
                ArgumentCaptor.forClass(SignedJWT.class);
        ArgumentCaptor<String> govukSigninJourneyIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> ipAddressCaptor = ArgumentCaptor.forClass(String.class);
        verify(ciMitService, times(1))
                .submitVC(
                        ciVerifiableCredentialCaptor.capture(),
                        govukSigninJourneyIdCaptor.capture(),
                        ipAddressCaptor.capture());
        List<SignedJWT> ciVerifiableCredentials = ciVerifiableCredentialCaptor.getAllValues();
        assertEquals(1, ciVerifiableCredentials.size());
        assertEquals(SIGNED_VC_1, ciVerifiableCredentials.get(0).serialize());
        List<String> ciJourneyIds = govukSigninJourneyIdCaptor.getAllValues();
        assertEquals(1, ciJourneyIds.size());
        assertNull(ciJourneyIds.get(0));
        List<String> ciIpAddresses = ipAddressCaptor.getAllValues();
        assertEquals(1, ciIpAddresses.size());
        assertNull(ciIpAddresses.get(0));
    }

    private void verifyCiStorageServicePostMitigations() throws CiPostMitigationsException {
        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> postedVcsCaptor = ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<String> govukSigninJourneyIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> ipAddressCaptor = ArgumentCaptor.forClass(String.class);
        verify(ciMitService, times(1))
                .submitMitigatingVcList(
                        postedVcsCaptor.capture(),
                        govukSigninJourneyIdCaptor.capture(),
                        ipAddressCaptor.capture());
        var postedVcs = postedVcsCaptor.getValue();
        assertEquals(1, postedVcs.size());
        assertEquals(SIGNED_VC_1, postedVcs.get(0));
        List<String> ciJourneyIds = govukSigninJourneyIdCaptor.getAllValues();
        assertEquals(1, ciJourneyIds.size());
        assertNull(ciJourneyIds.get(0));
        List<String> ciIpAddresses = ipAddressCaptor.getAllValues();
        assertEquals(1, ciIpAddresses.size());
        assertNull(ciIpAddresses.get(0));
    }

    private void verifyVerifiableCredentialService() {
        ArgumentCaptor<SignedJWT> storableVerifiableCredentialCaptor =
                ArgumentCaptor.forClass(SignedJWT.class);
        ArgumentCaptor<String> credentialIssuerCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> userIdCaptor = ArgumentCaptor.forClass(String.class);
        verify(verifiableCredentialService, times(1))
                .persistUserCredentials(
                        storableVerifiableCredentialCaptor.capture(),
                        credentialIssuerCaptor.capture(),
                        userIdCaptor.capture());
        List<SignedJWT> storedVerifiableCredentials =
                storableVerifiableCredentialCaptor.getAllValues();
        assertEquals(1, storedVerifiableCredentials.size());
        assertEquals(SIGNED_VC_1, storedVerifiableCredentials.get(0).serialize());
        List<String> credentialIssuers = credentialIssuerCaptor.getAllValues();
        assertEquals(1, credentialIssuers.size());
        assertEquals(TEST_CREDENTIAL_ISSUER_ID, credentialIssuers.get(0));
        List<String> userIds = userIdCaptor.getAllValues();
        assertEquals(1, userIds.size());
        assertEquals(TEST_USER_ID, userIds.get(0));
    }

    private void verifyVerifiableCredentialNotProcessedFurther()
            throws CiPutException, CiPostMitigationsException, SqsException {
        verify(auditService, never())
                .sendAuditEvent(ArgumentCaptor.forClass(AuditEvent.class).capture());
        verify(verifiableCredentialService, never()).persistUserCredentials(any(), any(), any());
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
        when(configService.getCredentialIssuerActiveConnectionConfig(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(TEST_CREDENTIAL_ISSUER_CONFIG);
        when(configService.getComponentId(ADDRESS_CRI))
                .thenReturn(TEST_CREDENTIAL_ISSUER_CONFIG_ADDRESS.getComponentId());
        when(configService.getComponentId(CLAIMED_IDENTITY_CRI))
                .thenReturn(TEST_CREDENTIAL_ISSUER_CONFIG_CLAIMED_IDENTITY.getComponentId());
    }
}
