package uk.gov.di.ipv.core.manualf2fpendingreset;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ManualF2fPendingResetHandlerTest {

    private static final String TEST_USER_ID = "test-user-id";

    @Mock private Context mockContext;
    @Mock private CriResponseService mockCriResponseService;
    @Mock private ConfigService mockConfigService;

    @InjectMocks private ManualF2fPendingResetHandler handler;

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void shouldReturnErrorForInvalidInput(String invalidInput) {
        Map<String, Object> response = handler.handleRequest(invalidInput, mockContext);
        assertEquals("error", response.get("result"));
        assertEquals("Missing or empty userId in input", response.get("message"));
    }

    @Test
    void shouldReturnErrorWhenCriResponseItemNotFound() {
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(null);

        Map<String, Object> response = handler.handleRequest(TEST_USER_ID, mockContext);

        assertEquals("error", response.get("result"));
        assertEquals("No F2F pending record found.", response.get("message"));
        verify(mockCriResponseService, never()).deleteCriResponseItem(TEST_USER_ID, Cri.F2F);
    }

    @Test
    void shouldReturnSuccessWhenItemFoundAndDeleted() {
        CriResponseItem mockItem =
                CriResponseItem.builder()
                        .userId(TEST_USER_ID)
                        .credentialIssuer(Cri.F2F.getId())
                        .build();

        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(mockItem);

        Map<String, Object> response = handler.handleRequest(TEST_USER_ID, mockContext);

        assertEquals("success", response.get("result"));
        assertEquals("Deleted F2F pending record.", response.get("message"));
        verify(mockCriResponseService).deleteCriResponseItem(TEST_USER_ID, Cri.F2F);
    }

    @Test
    void shouldReturnErrorWhenExceptionThrownDuringLookup() {
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F))
                .thenThrow(new RuntimeException("simulated failure"));

        Map<String, Object> response = handler.handleRequest(TEST_USER_ID, mockContext);

        assertEquals("error", response.get("result"));
        assertEquals("Failed to delete record due to internal error.", response.get("message"));
    }

    @Test
    void responseShouldAlwaysContainResultAndMessageFields() {
        when(mockCriResponseService.getCriResponseItem(TEST_USER_ID, Cri.F2F)).thenReturn(null);

        Map<String, Object> response = handler.handleRequest(TEST_USER_ID, mockContext);

        assertTrue(response.containsKey("result"));
        assertTrue(response.containsKey("message"));
    }
}
