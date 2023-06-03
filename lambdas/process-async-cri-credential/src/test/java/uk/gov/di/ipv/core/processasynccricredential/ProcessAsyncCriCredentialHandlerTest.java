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
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.CiPutException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validation.VerifiableCredentialJwtValidator;
import uk.gov.di.ipv.core.processasynccricredential.dto.CriResponseMessageDto;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

@ExtendWith(MockitoExtension.class)
class ProcessAsyncCriCredentialHandlerTest {

    private static final String TEST_MESSAGE_ID = UUID.randomUUID().toString();
    private static final String TEST_CREDENTIAL_ISSUER_ID = "f2f";
    private static final String TEST_USER_ID = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    private static final String TEST_COMPONENT_ID = "f2f";
    private static final String TEST_OAUTH_STATE = UUID.randomUUID().toString();
    private static final CriResponseItem TEST_CRI_RESPONSE_ITEM =
            new CriResponseItem(
                    TEST_USER_ID, TEST_CREDENTIAL_ISSUER_ID, null, TEST_OAUTH_STATE, null, null, 0);

    private static final String TEST_ASYNC_ERROR = "access_denied";
    private static final String TEST_ASYNC_ERROR_DESCRIPTION =
            "Additional information on the error";
    private static final CredentialIssuerConfig TEST_CREDENTIAL_ISSUER_CONFIG;
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
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    @Mock private ConfigService configService;
    @Mock private VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    @Mock private VerifiableCredentialService verifiableCredentialService;
    @Mock private AuditService auditService;
    @Mock private CiStorageService ciStorageService;
    @Mock private CriResponseService criResponseService;

    @InjectMocks private ProcessAsyncCriCredentialHandler handler;

    @Test
    void shouldProcessValidExpectedAsyncVerifiableCredentialSuccessfully()
            throws JsonProcessingException, SqsException, CiPutException {
        final SQSEvent testEvent = createSuccessTestEvent();
        mockServiceCalls();

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);
        assertEquals(0, batchResponse.getBatchItemFailures().size());

        verifyVerifiableCredentialJwtValidator();
        verifyCiStorageService();
        verifyVerifiableCredentialService();
        verifyAuditService();
    }

    @Test
    void shouldProcessErrorAsyncVerifiableCredentialSuccessfully() throws JsonProcessingException {
        final SQSEvent testEvent = createErrorTestEvent();

        final SQSBatchResponse batchResponse = handler.handleRequest(testEvent, null);
        assertEquals(0, batchResponse.getBatchItemFailures().size());
    }

    @Test
    void shouldRejectValidUnexpectedVerifiableCredential() {}

    @Test
    void shouldRejectValidExpiredVerifiableCredential() {}

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

    private SQSEvent createSuccessTestEvent() throws JsonProcessingException {
        final SQSEvent sqsEvent = new SQSEvent();
        final CriResponseMessageDto criResponseMessageDto =
                new CriResponseMessageDto(
                        null, TEST_USER_ID, TEST_OAUTH_STATE, List.of(SIGNED_VC_1), null, null);
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

    private void mockServiceCalls() {
        when(configService.getCredentialIssuerActiveConnectionConfig(TEST_CREDENTIAL_ISSUER_ID))
                .thenReturn(TEST_CREDENTIAL_ISSUER_CONFIG);
        when(configService.getCredentialIssuerActiveConnectionConfig("address"))
                .thenReturn(TEST_CREDENTIAL_ISSUER_CONFIG);
        when(criResponseService.getCriResponseItem(TEST_USER_ID, TEST_COMPONENT_ID))
                .thenReturn(TEST_CRI_RESPONSE_ITEM);
    }

    private void verifyCiStorageService() throws CiPutException {
        ArgumentCaptor<SignedJWT> ciVerifiableCredentialCaptor =
                ArgumentCaptor.forClass(SignedJWT.class);
        ArgumentCaptor<String> govukSigninJourneyIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> ipAddressCaptor = ArgumentCaptor.forClass(String.class);
        verify(ciStorageService, times(1))
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
}
