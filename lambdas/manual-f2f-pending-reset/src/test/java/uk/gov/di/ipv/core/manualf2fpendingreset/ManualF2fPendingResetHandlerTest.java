package uk.gov.di.ipv.core.manualf2fpendingreset;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.exceptions.ManualF2fPendingResetException;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_F2F_SUPPORT_CANCEL;

@ExtendWith(MockitoExtension.class)
class ManualF2fPendingResetHandlerTest {

    private static final String TEST_USER_ID = "test-user-id";

    @Mock private Context mockContext;
    @Mock private CriResponseService mockCriResponseService;
    @Mock private ConfigService mockConfigService;
    @Mock private Config mockConfig;
    @Mock private AuditService auditService;
    @Captor private ArgumentCaptor<AuditEvent> auditEventCaptor;

    @InjectMocks private ManualF2fPendingResetHandler handler;

    @BeforeEach
    void setUp() {
        when(mockConfigService.getComponentId()).thenReturn("https://core-component.example");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void shouldThrowExceptionForInvalidInput(String invalidInput) {
        assertThrows(
                ManualF2fPendingResetException.class,
                () -> handler.handleRequest(invalidInput, mockContext));

        verify(auditService, times(1)).awaitAuditEvents();
    }

    @Test
    void shouldThrowExceptionWhenCriResponseItemNotFound() {
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(null);

        var ex =
                assertThrows(
                        ManualF2fPendingResetException.class,
                        () -> handler.handleRequest(TEST_USER_ID, mockContext));

        assertEquals("No F2F pending record found.", ex.getMessage());
        verify(mockCriResponseService, never()).deleteCriResponseItem(TEST_USER_ID, Cri.F2F);
        verify(auditService, never()).sendAuditEvent(any());
        verify(auditService, times(1)).awaitAuditEvents();
    }

    @Test
    void shouldThrowExceptionWhenLookupFails() {
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F))
                .thenThrow(new RuntimeException("simulated failure"));

        assertThrows(
                ManualF2fPendingResetException.class,
                () -> handler.handleRequest(TEST_USER_ID, mockContext));

        verify(mockCriResponseService, never()).deleteCriResponseItem(TEST_USER_ID, Cri.F2F);
        verify(auditService, never()).sendAuditEvent(any());
        verify(auditService, times(1)).awaitAuditEvents();
    }

    @Test
    void shouldThrowExceptionWhenDeleteFails() {
        CriResponseItem mockItem =
                CriResponseItem.builder()
                        .userId(TEST_USER_ID)
                        .credentialIssuer(Cri.F2F.getId())
                        .build();
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(mockItem);
        doThrow(new RuntimeException("delete failed"))
                .when(mockCriResponseService)
                .deleteCriResponseItem(TEST_USER_ID, Cri.F2F);

        assertThrows(
                ManualF2fPendingResetException.class,
                () -> handler.handleRequest(TEST_USER_ID, mockContext));

        verify(mockCriResponseService).deleteCriResponseItem(TEST_USER_ID, Cri.F2F);
        verify(auditService, never()).sendAuditEvent(any());
        verify(auditService, times(1)).awaitAuditEvents();
    }

    @Test
    void shouldReturnSuccessWhenItemFoundAndDeleted() {
        CriResponseItem mockItem =
                CriResponseItem.builder()
                        .userId(TEST_USER_ID)
                        .credentialIssuer(Cri.F2F.getId())
                        .build();
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(mockItem);

        var response = handler.handleRequest(TEST_USER_ID, mockContext);

        assertEquals("success", response.get("result"));
        assertEquals("Deleted F2F pending record.", response.get("message"));
        verify(mockCriResponseService).deleteCriResponseItem(TEST_USER_ID, Cri.F2F);
        verify(auditService).sendAuditEvent(any());
        verify(auditService, times(1)).awaitAuditEvents();
    }

    @Test
    void shouldSendAuditEventWithUserId() {
        CriResponseItem mockItem =
                CriResponseItem.builder()
                        .userId(TEST_USER_ID)
                        .credentialIssuer(Cri.F2F.getId())
                        .build();
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(mockItem);

        handler.handleRequest(TEST_USER_ID, mockContext);

        verify(auditService).sendAuditEvent(auditEventCaptor.capture());
        var auditEvent = auditEventCaptor.getValue();

        assertEquals(IPV_F2F_SUPPORT_CANCEL, auditEvent.getEventName());
        assertEquals(TEST_USER_ID, auditEvent.getUser().getUserId());
        verify(auditService, times(1)).awaitAuditEvents();
    }

    @Test
    void shouldThrowExceptionOnUnexpectedError() {
        doThrow(new RuntimeException("unexpected")).when(auditService).awaitAuditEvents();

        CriResponseItem mockItem =
                CriResponseItem.builder()
                        .userId(TEST_USER_ID)
                        .credentialIssuer(Cri.F2F.getId())
                        .build();
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(mockItem);

        assertThrows(
                RuntimeException.class, () -> handler.handleRequest(TEST_USER_ID, mockContext));
    }
}
