package uk.gov.di.ipv.core.reportuseridentity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.io.InputStream;
import java.io.OutputStream;

@ExtendWith(MockitoExtension.class)
class ReportUserIdentityHandlerTest {
    private final String TEST_USER_ID = "urn:uuid:0369ce52-b72d-42f5-83d4-ab561fa01fd7";
    @Mock private InputStream inputStream;
    @Mock private OutputStream outputStream;
    @Mock private ConfigService mockConfigService;
    @Mock private DataStore<VcStoreItem> mockDataStore;
    @InjectMocks private ReportUserIdentityHandler reportUserIdentityHandler;

    @Test
    void shouldRunReportToGenerateusersIdentity() throws Exception {
        // Arrange

        // Act
        reportUserIdentityHandler.handleRequest(inputStream, outputStream, null);

        // Assert
    }
}
