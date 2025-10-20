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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
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
        // Act + Assert
        var ex =
                assertThrows(
                        ManualF2fPendingResetException.class,
                        () -> handler.handleRequest(invalidInput, mockContext));

        assertEquals("Missing or empty userId in input", ex.getMessage());
        verify(auditService).awaitAuditEvents();
    }

    @Test
    void shouldAlwaysAwaitAuditEventsEvenIfExceptionThrown() {
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F))
                .thenThrow(new RuntimeException("boom"));

        assertThrows(
                ManualF2fPendingResetException.class,
                () -> handler.handleRequest(TEST_USER_ID, mockContext));

        verify(auditService).awaitAuditEvents();
    }

    @Test
    void shouldThrowExceptionWhenNoPendingRecordFound() {
        // Arrange
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(null);

        // Act
        var ex =
                assertThrows(
                        ManualF2fPendingResetException.class,
                        () -> handler.handleRequest(TEST_USER_ID, mockContext));

        // Assert
        assertEquals("No F2F pending record found.", ex.getMessage());
        verify(mockCriResponseService, never()).deleteCriResponseItem(TEST_USER_ID, Cri.F2F);
        verify(auditService, never()).sendAuditEvent(any());
        verify(auditService).awaitAuditEvents();
    }

    @Test
    void shouldThrowExceptionWhenLookupFails() {
        // Arrange
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F))
                .thenThrow(new RuntimeException("simulated failure"));

        // Act + Assert
        var ex =
                assertThrows(
                        ManualF2fPendingResetException.class,
                        () -> handler.handleRequest(TEST_USER_ID, mockContext));

        assertTrue(
                ex.getMessage().contains("Unexpected failure in Manual F2F Pending Reset Lambda"));
        verify(mockCriResponseService, never()).deleteCriResponseItem(TEST_USER_ID, Cri.F2F);
        verify(auditService, never()).sendAuditEvent(any());
        verify(auditService).awaitAuditEvents();
    }

    @Test
    void shouldWrapExceptionWhenAuditEventFails() {
        // Arrange
        CriResponseItem mockItem =
                CriResponseItem.builder()
                        .userId(TEST_USER_ID)
                        .credentialIssuer(Cri.F2F.getId())
                        .build();
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(mockItem);
        doThrow(new RuntimeException("audit send failed"))
                .when(auditService)
                .sendAuditEvent(any(AuditEvent.class));

        // Act + Assert
        var ex =
                assertThrows(
                        ManualF2fPendingResetException.class,
                        () -> handler.handleRequest(TEST_USER_ID, mockContext));

        assertTrue(
                ex.getMessage().contains("Unexpected failure in Manual F2F Pending Reset Lambda"));
        verify(auditService).awaitAuditEvents();
    }

    @Test
    void shouldReturnSuccessWhenItemFoundAndDeleted() {
        // Arrange
        CriResponseItem mockItem =
                CriResponseItem.builder()
                        .userId(TEST_USER_ID)
                        .credentialIssuer(Cri.F2F.getId())
                        .build();
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(mockItem);

        // Act
        var response = handler.handleRequest(TEST_USER_ID, mockContext);

        // Assert
        assertEquals("success", response.get("result"));
        assertEquals("Deleted F2F pending record.", response.get("message"));
        verify(mockCriResponseService).deleteCriResponseItem(TEST_USER_ID, Cri.F2F);
        verify(auditService).sendAuditEvent(any());
        verify(auditService).awaitAuditEvents();
    }

    @Test
    void shouldSendAuditEventWithUserId() {
        // Arrange
        CriResponseItem mockItem =
                CriResponseItem.builder()
                        .userId(TEST_USER_ID)
                        .credentialIssuer(Cri.F2F.getId())
                        .build();
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(mockItem);

        // Act
        handler.handleRequest(TEST_USER_ID, mockContext);

        // Assert
        verify(auditService).sendAuditEvent(auditEventCaptor.capture());
        var auditEvent = auditEventCaptor.getValue();

        assertEquals(IPV_F2F_SUPPORT_CANCEL, auditEvent.getEventName());
        assertEquals(TEST_USER_ID, auditEvent.getUser().getUserId());
        verify(auditService).awaitAuditEvents();
    }

    @Test
    void shouldThrowRuntimeExceptionIfAuditFails() {
        // Arrange
        doThrow(new RuntimeException("unexpected")).when(auditService).awaitAuditEvents();

        CriResponseItem mockItem =
                CriResponseItem.builder()
                        .userId(TEST_USER_ID)
                        .credentialIssuer(Cri.F2F.getId())
                        .build();
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(mockItem);

        // Act + Assert
        assertThrows(
                RuntimeException.class, () -> handler.handleRequest(TEST_USER_ID, mockContext));
    }
}
