package uk.gov.di.ipv.core.reportuseridentity;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportProcessingRequest;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportProcessingResult;
import uk.gov.di.ipv.core.reportuseridentity.domain.TableScanResult;
import uk.gov.di.ipv.core.reportuseridentity.persistence.DataStore;
import uk.gov.di.ipv.core.reportuseridentity.persistence.item.ReportUserIdentityItem;
import uk.gov.di.ipv.core.reportuseridentity.service.ReportUserIdentityService;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.TEST_SUBJECT;
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
    @Mock private ReportUserIdentityService mockReportUserIdentityService;

    @Mock(name = "vcStoreItemDataStore")
    private DataStore<VcStoreItem> mockVcStoreItemDataStore;

    @Mock(name = "reportUserIdentityDataStore")
    private DataStore<ReportUserIdentityItem> mockReportUserIdentityDataStore;

    @Captor private ArgumentCaptor<ReportProcessingResult> reportProcessingResultArgumentCaptor;
    private ReportUserIdentityHandler reportUserIdentityHandler;

    @BeforeEach
    public void setUp() {
        reportUserIdentityHandler =
                new ReportUserIdentityHandler(
                        objectMapper,
                        mockConfigService,
                        mockUserIdentityService,
                        mockVerifiableCredentialService,
                        mockReportUserIdentityService,
                        mockVcStoreItemDataStore,
                        mockReportUserIdentityDataStore);
    }

    @Test
    void shouldRunReportToGenerateUsersIdentity() throws Exception {
        var credentials =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.toVcStoreItem(),
                        VC_ADDRESS.toVcStoreItem(),
                        vcExperianFraudScoreTwo().toVcStoreItem());
        // Arrange
        when(objectMapper.readValue(inputStream, ReportProcessingRequest.class))
                .thenReturn(new ReportProcessingRequest(false, null, null));
        when(mockVcStoreItemDataStore.getItems(any(), any()))
                .thenReturn(new TableScanResult<>(credentials, null));
        when(mockVerifiableCredentialService.getVcs(TEST_SUBJECT))
                .thenReturn(List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, VC_ADDRESS));
        String userId2 = "urn:uuid:7fadacac-0d61-4786-aca3-8ef7934cb092";
        when(mockVerifiableCredentialService.getVcs(userId2))
                .thenReturn(List.of(vcExperianFraudScoreTwo()));
        when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(Boolean.TRUE);
        when(mockReportUserIdentityService.getStrongestAttainedVotForCredentials(any()))
                .thenReturn(Optional.of(Vot.P2));
        List<ReportUserIdentityItem> totalIdentities =
                List.of(
                        new ReportUserIdentityItem(
                                TEST_SUBJECT, "P2", 0, Collections.emptyList(), true),
                        new ReportUserIdentityItem(
                                userId2, "P2", 0, Collections.emptyList(), false));
        when(mockReportUserIdentityDataStore.getItems(any(), any(), any()))
                .thenReturn(new TableScanResult<>(totalIdentities, null));
        // Act
        reportUserIdentityHandler.handleRequest(inputStream, outputStream, null);

        // Assert
        verify(mockReportUserIdentityDataStore, times(2)).createOrUpdate(any());
        verify(objectMapper)
                .writeValue(
                        any(OutputStream.class), reportProcessingResultArgumentCaptor.capture());
        var reportProcessingResult = reportProcessingResultArgumentCaptor.getValue();
        long totalP2Identities =
                totalIdentities.stream().filter(i -> Vot.P2.name().equals(i.getIdentity())).count();
        assertEquals(totalP2Identities, reportProcessingResult.summary().totalP2Identities());
        assertEquals(
                (totalP2Identities - 1),
                reportProcessingResult.summary().totalP2IdentitiesMigrated());
    }
}
