package uk.gov.di.ipv.core.reportuseridentity;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportProcessingResult;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.VC_ADDRESS;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreTwo;

@ExtendWith(MockitoExtension.class)
class ReportUserIdentityHandlerTest {
    @Mock ObjectMapper objectMapper;
    @Mock private InputStream inputStream;
    @Mock private OutputStream outputStream;
    @Mock private ConfigService mockConfigService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private DataStore<VcStoreItem> mockVcStoreItemDataStore;
    //    @Mock private DataStore<ReportUserIdentityItem> mockReportUserIdentityDataStore;
    @Captor private ArgumentCaptor<ReportProcessingResult> reportProcessingResultArgumentCaptor;
    @InjectMocks private ReportUserIdentityHandler reportUserIdentityHandler;

    @Test
    void shouldRunReportToGenerateUsersIdentity() throws Exception {
        var credentials =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.toVcStoreItem(),
                        VC_ADDRESS.toVcStoreItem(),
                        vcExperianFraudScoreTwo().toVcStoreItem());
        // Arrange
        when(mockVcStoreItemDataStore.getItems()).thenReturn(credentials);
        // Act
        reportUserIdentityHandler.handleRequest(inputStream, outputStream, null);

        // Assert
        verify(objectMapper)
                .writeValue(
                        any(OutputStream.class), reportProcessingResultArgumentCaptor.capture());
        var reportProcessingResult = reportProcessingResultArgumentCaptor.getValue();
        assertEquals(0l, reportProcessingResult.summary().totalP2Identities());
    }
}
