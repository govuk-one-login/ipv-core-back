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
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportProcessingResult;
import uk.gov.di.ipv.core.reportuseridentity.domain.item.ReportUserIdentityItem;
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
import static uk.gov.di.ipv.core.reportuseridentity.ReportUserIdentityHandler.ATTR_NAME_TO_SUMMARISE_ON;

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
        when(mockVcStoreItemDataStore.getItems()).thenReturn(credentials);
        when(mockVerifiableCredentialService.getVcs(TEST_SUBJECT))
                .thenReturn(List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, VC_ADDRESS));
        String userId2 = "urn:uuid:7fadacac-0d61-4786-aca3-8ef7934cb092";
        when(mockVerifiableCredentialService.getVcs(userId2))
                .thenReturn(List.of(vcExperianFraudScoreTwo()));
        when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(Boolean.TRUE);
        when(mockReportUserIdentityService.getStrongestAttainedVotForCredentials(any()))
                .thenReturn(Optional.of(Vot.P2));
        List<ReportUserIdentityItem> totalP2Identities =
                List.of(
                        new ReportUserIdentityItem(
                                TEST_SUBJECT, "P2", Collections.emptyList(), true),
                        new ReportUserIdentityItem(userId2, "P2", Collections.emptyList(), false));
        when(mockReportUserIdentityDataStore.getItems(ATTR_NAME_TO_SUMMARISE_ON, Vot.P2.name()))
                .thenReturn(totalP2Identities);
        // Act
        reportUserIdentityHandler.handleRequest(inputStream, outputStream, null);

        // Assert
        verify(mockReportUserIdentityDataStore, times(2)).createOrUpdate(any());
        verify(objectMapper)
                .writeValue(
                        any(OutputStream.class), reportProcessingResultArgumentCaptor.capture());
        var reportProcessingResult = reportProcessingResultArgumentCaptor.getValue();
        assertEquals(
                totalP2Identities.size(), reportProcessingResult.summary().totalP2Identities());
        assertEquals(
                (totalP2Identities.size() - 1),
                reportProcessingResult.summary().totalP2IdentitiesMigrated());
    }
}
