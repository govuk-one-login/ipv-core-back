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
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.testhelpers.unit.ConfigServiceHelper;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
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
        ConfigServiceHelper.stubDefaultComponentIdConfig(mockConfigService, mockConfig);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void shouldReturnErrorForInvalidInput(String invalidInput) {
        // Act
        Map<String, Object> response = handler.handleRequest(invalidInput, mockContext);

        // Assert
        assertEquals("error", response.get("result"));
        assertEquals("Missing or empty userId in input", response.get("message"));
    }

    @Test
    void shouldReturnErrorWhenCriResponseItemNotFound() {
        // Arrange
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(null);

        // Act
        Map<String, Object> response = handler.handleRequest(TEST_USER_ID, mockContext);

        // Assert
        assertEquals("error", response.get("result"));
        assertEquals("No F2F pending record found.", response.get("message"));
        verify(mockCriResponseService, never()).deleteCriResponseItem(TEST_USER_ID, Cri.F2F);
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
        Map<String, Object> response = handler.handleRequest(TEST_USER_ID, mockContext);

        // Assert
        assertEquals("success", response.get("result"));
        assertEquals("Deleted F2F pending record.", response.get("message"));
        verify(mockCriResponseService).deleteCriResponseItem(TEST_USER_ID, Cri.F2F);
    }

    @Test
    void shouldReturnErrorWhenExceptionThrownDuringLookup() {
        // Arrange
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F))
                .thenThrow(new RuntimeException("simulated failure"));

        // Act
        Map<String, Object> response = handler.handleRequest(TEST_USER_ID, mockContext);

        // Assert
        assertEquals("error", response.get("result"));
        assertEquals("Failed to delete record due to internal error.", response.get("message"));
    }

    @Test
    void responseShouldAlwaysContainResultAndMessageFields() {
        // Arrange
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(null);

        // Act
        Map<String, Object> response = handler.handleRequest(TEST_USER_ID, mockContext);

        // Assert
        assertTrue(response.containsKey("result"));
        assertTrue(response.containsKey("message"));
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
        verify(auditService, times(1)).awaitAuditEvents();
    }

    @Test
    void shouldNotSendAuditEvent() {
        // Arrange
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(null);

        // Act
        handler.handleRequest(TEST_USER_ID, mockContext);

        // Assert
        verify(auditService, times(0)).sendAuditEvent(any());
    }
}
