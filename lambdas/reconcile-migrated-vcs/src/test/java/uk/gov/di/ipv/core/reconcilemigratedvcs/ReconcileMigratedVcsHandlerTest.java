package uk.gov.di.ipv.core.reconcilemigratedvcs;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.client.EvcsClient;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.dto.EvcsGetUserVCDto;
import uk.gov.di.ipv.core.library.dto.EvcsGetUserVCsDto;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;
import uk.gov.di.ipv.core.library.factories.EvcsClientFactory;
import uk.gov.di.ipv.core.library.factories.ForkJoinPoolFactory;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.reconcilemigratedvcs.domain.Request;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.DRIVING_LICENCE;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.Cri.PASSPORT;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_AT_EVCS_HTTP_REQUEST_SEND;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_SIGNING_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.DCMAW_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_RSA_SIGNED_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudMissingName;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;

@ExtendWith(MockitoExtension.class)
class ReconcileMigratedVcsHandlerTest {

    @Mock private Context mockContext;
    @Mock private ForkJoinPool mockForkJoinPool;
    @Mock private ForkJoinTask mockForkJoinTask;
    @Mock private EvcsClient mockEvcsClient;
    @Mock private ConfigService mockConfigService;
    @Mock private ForkJoinPoolFactory mockForkJoinPoolFactory;
    @Mock private EvcsClientFactory mockEvcsClientFactory;
    @Mock private Gpg45ProfileEvaluator mockGpg45ProfileEvaluator;
    @Mock private DataStore<VcStoreItem> mockTacticalDataStore;
    @InjectMocks private ReconcileMigratedVcsHandler handler;

    @Test
    void handlerShouldHandleMatchingVcs() throws Exception {
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
        when(mockEvcsClientFactory.getClient()).thenReturn(mockEvcsClient);
        when(mockEvcsClient.getUserVcsForMigrationReconciliation("userId1"))
                .thenReturn(
                        new EvcsGetUserVCsDto(
                                List.of(
                                        evcsGetDtoOf(DCMAW_PASSPORT_VC.getVcString()),
                                        evcsGetDtoOf(M1A_EXPERIAN_FRAUD_VC.getVcString()),
                                        evcsGetDtoOf(M1A_ADDRESS_VC.getVcString()))));
        when(mockTacticalDataStore.getItems("userId1"))
                .thenReturn(
                        List.of(
                                vcStoreItemOf(DCMAW_PASSPORT_VC.getVcString()),
                                vcStoreItemOf(M1A_EXPERIAN_FRAUD_VC.getVcString()),
                                vcStoreItemOf(M1A_ADDRESS_VC.getVcString())));
        var request = new Request("vcs-match-batch-id", List.of("userId1"), 4, false, false);

        var reconciliationReport = handler.handleRequest(request, mockContext);

        assertEquals("vcs-match-batch-id", reconciliationReport.getBatchId());
        assertEquals(1, reconciliationReport.getBatchSize());
        assertEquals(1, reconciliationReport.getIdentitiesFullyProcessed());
        assertEquals(1, reconciliationReport.getVcsMatchedCount());
        assertEquals(0, reconciliationReport.getVcsDifferentCount());
        assertFalse(reconciliationReport.isCheckSignatures());
        assertFalse(reconciliationReport.isCheckP2());
    }

    @Test
    void handlerShouldHandleNonMatchingVcs() throws Exception {
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
        when(mockEvcsClientFactory.getClient()).thenReturn(mockEvcsClient);
        when(mockEvcsClient.getUserVcsForMigrationReconciliation("userId1"))
                .thenReturn(
                        new EvcsGetUserVCsDto(
                                List.of(
                                        evcsGetDtoOf(DCMAW_PASSPORT_VC.getVcString()),
                                        evcsGetDtoOf(M1A_EXPERIAN_FRAUD_VC.getVcString()),
                                        evcsGetDtoOf(M1A_ADDRESS_VC.getVcString()))));
        when(mockTacticalDataStore.getItems("userId1"))
                .thenReturn(
                        List.of(
                                vcStoreItemOf(DCMAW_PASSPORT_VC.getVcString()),
                                vcStoreItemOf(M1A_EXPERIAN_FRAUD_VC.getVcString()),
                                vcStoreItemOf(M1A_ADDRESS_VC.getVcString().toLowerCase())));
        var request = new Request("vcs-no-match-batch-id", List.of("userId1"), null, false, false);

        var reconciliationReport = handler.handleRequest(request, mockContext);

        assertEquals("vcs-no-match-batch-id", reconciliationReport.getBatchId());
        assertEquals(1, reconciliationReport.getBatchSize());
        assertEquals(1, reconciliationReport.getIdentitiesFullyProcessed());
        assertEquals(0, reconciliationReport.getVcsMatchedCount());
        assertEquals(1, reconciliationReport.getVcsDifferentCount());
        assertFalse(reconciliationReport.isCheckSignatures());
        assertFalse(reconciliationReport.isCheckP2());
    }

    @Test
    void handlerShouldHandleMissingVcs() throws Exception {
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
        when(mockEvcsClientFactory.getClient()).thenReturn(mockEvcsClient);
        when(mockEvcsClient.getUserVcsForMigrationReconciliation("userId1"))
                .thenReturn(
                        new EvcsGetUserVCsDto(
                                List.of(
                                        evcsGetDtoOf(DCMAW_PASSPORT_VC.getVcString()),
                                        evcsGetDtoOf(M1A_ADDRESS_VC.getVcString()))));
        when(mockTacticalDataStore.getItems("userId1"))
                .thenReturn(
                        List.of(
                                vcStoreItemOf(DCMAW_PASSPORT_VC.getVcString()),
                                vcStoreItemOf(M1A_EXPERIAN_FRAUD_VC.getVcString()),
                                vcStoreItemOf(M1A_ADDRESS_VC.getVcString())));
        var request = new Request("vcs-missing-batch-id", List.of("userId1"), 4, false, false);

        var reconciliationReport = handler.handleRequest(request, mockContext);

        assertEquals("vcs-missing-batch-id", reconciliationReport.getBatchId());
        assertEquals(1, reconciliationReport.getBatchSize());
        assertEquals(1, reconciliationReport.getIdentitiesFullyProcessed());
        assertEquals(0, reconciliationReport.getVcsMatchedCount());
        assertEquals(1, reconciliationReport.getVcsDifferentCount());
        assertFalse(reconciliationReport.isCheckSignatures());
        assertFalse(reconciliationReport.isCheckP2());
    }

    @Test
    void handlerShouldHandleValidateSignatures() throws Exception {
        var ecVc = vcExperianFraudMissingName();
        var rsaVc = PASSPORT_NON_DCMAW_SUCCESSFUL_RSA_SIGNED_VC;

        when(mockConfigService.getAllCrisByIssuer())
                .thenReturn(
                        Map.of(
                                ecVc.getClaimsSet().getIssuer(), EXPERIAN_FRAUD,
                                rsaVc.getClaimsSet().getIssuer(), PASSPORT));
        mockHistoricSigningKeysExcept("fraud", "ukPassport");
        when(mockConfigService.getHistoricSigningKeys("fraud"))
                .thenReturn(List.of(TEST_EC_PUBLIC_JWK));
        when(mockConfigService.getHistoricSigningKeys("ukPassport"))
                .thenReturn(List.of(RSA_SIGNING_PUBLIC_JWK));

        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
        when(mockEvcsClientFactory.getClient()).thenReturn(mockEvcsClient);
        when(mockEvcsClient.getUserVcsForMigrationReconciliation("userId1"))
                .thenReturn(
                        new EvcsGetUserVCsDto(
                                List.of(
                                        evcsGetDtoOf(ecVc.getVcString()),
                                        evcsGetDtoOf(rsaVc.getVcString()))));
        when(mockTacticalDataStore.getItems("userId1"))
                .thenReturn(
                        List.of(
                                vcStoreItemOf(ecVc.getVcString()),
                                vcStoreItemOf(rsaVc.getVcString())));
        var request = new Request("vcs-valid-sig-batch-id", List.of("userId1"), 4, true, false);

        var reconciliationReport = handler.handleRequest(request, mockContext);

        assertTrue(reconciliationReport.isCheckSignatures());
        assertEquals("vcs-valid-sig-batch-id", reconciliationReport.getBatchId());
        assertEquals(1, reconciliationReport.getBatchSize());
        assertEquals(1, reconciliationReport.getIdentitiesFullyProcessed());
        assertEquals(1, reconciliationReport.getVcsMatchedCount());
        assertEquals(0, reconciliationReport.getVcsDifferentCount());
        assertEquals(1, reconciliationReport.getIdentityWithValidSignaturesCount());
        assertEquals(0, reconciliationReport.getIdentityWithInvalidSignaturesCount());
        assertEquals(0, reconciliationReport.getInvalidVcSignatureCount());
        assertFalse(reconciliationReport.isCheckP2());
    }

    @Test
    void handlerShouldHandleInvalidSignatures() throws Exception {
        var vc = vcDrivingPermit();
        when(mockConfigService.getAllCrisByIssuer())
                .thenReturn(Map.of(vc.getClaimsSet().getIssuer(), DRIVING_LICENCE));
        mockHistoricSigningKeysExcept("drivingLicence");
        when(mockConfigService.getHistoricSigningKeys("drivingLicence"))
                .thenReturn(List.of(EC_PUBLIC_JWK_2));
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
        when(mockEvcsClientFactory.getClient()).thenReturn(mockEvcsClient);
        when(mockEvcsClient.getUserVcsForMigrationReconciliation("userId1"))
                .thenReturn(new EvcsGetUserVCsDto(List.of(evcsGetDtoOf(vc.getVcString()))));
        when(mockTacticalDataStore.getItems("userId1"))
                .thenReturn(List.of(vcStoreItemOf(vc.getVcString())));
        var request = new Request("vcs-valid-sig-batch-id", List.of("userId1"), 4, true, false);

        var reconciliationReport = handler.handleRequest(request, mockContext);

        assertTrue(reconciliationReport.isCheckSignatures());
        assertEquals("vcs-valid-sig-batch-id", reconciliationReport.getBatchId());
        assertEquals(1, reconciliationReport.getBatchSize());
        assertEquals(1, reconciliationReport.getIdentitiesFullyProcessed());
        assertEquals(1, reconciliationReport.getVcsMatchedCount());
        assertEquals(0, reconciliationReport.getVcsDifferentCount());
        assertEquals(0, reconciliationReport.getIdentityWithValidSignaturesCount());
        assertEquals(1, reconciliationReport.getIdentityWithInvalidSignaturesCount());
        assertEquals(1, reconciliationReport.getInvalidVcSignatureCount());
        assertFalse(reconciliationReport.isCheckP2());
    }

    @Test
    void handlerShouldCheckSignaturesWithAllKeys() throws Exception {
        var vc = vcDrivingPermit();
        when(mockConfigService.getAllCrisByIssuer())
                .thenReturn(Map.of(vc.getClaimsSet().getIssuer(), DRIVING_LICENCE));
        mockHistoricSigningKeysExcept("drivingLicence");
        when(mockConfigService.getHistoricSigningKeys("drivingLicence"))
                .thenReturn(List.of(EC_PUBLIC_JWK_2, TEST_EC_PUBLIC_JWK));
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
        when(mockEvcsClientFactory.getClient()).thenReturn(mockEvcsClient);
        when(mockEvcsClient.getUserVcsForMigrationReconciliation("userId1"))
                .thenReturn(new EvcsGetUserVCsDto(List.of(evcsGetDtoOf(vc.getVcString()))));
        when(mockTacticalDataStore.getItems("userId1"))
                .thenReturn(List.of(vcStoreItemOf(vc.getVcString())));
        var request = new Request("vcs-valid-sig-batch-id", List.of("userId1"), 4, true, false);

        var reconciliationReport = handler.handleRequest(request, mockContext);

        assertTrue(reconciliationReport.isCheckSignatures());
        assertEquals("vcs-valid-sig-batch-id", reconciliationReport.getBatchId());
        assertEquals(1, reconciliationReport.getBatchSize());
        assertEquals(1, reconciliationReport.getIdentitiesFullyProcessed());
        assertEquals(1, reconciliationReport.getVcsMatchedCount());
        assertEquals(0, reconciliationReport.getVcsDifferentCount());
        assertEquals(1, reconciliationReport.getIdentityWithValidSignaturesCount());
        assertEquals(0, reconciliationReport.getIdentityWithInvalidSignaturesCount());
        assertEquals(0, reconciliationReport.getInvalidVcSignatureCount());
        assertFalse(reconciliationReport.isCheckP2());
    }

    @Test
    void handlerShouldHandleIdentityWithP2() throws Exception {
        var vc = vcDrivingPermit();
        when(mockConfigService.getAllCrisByIssuer())
                .thenReturn(Map.of(vc.getClaimsSet().getIssuer(), DRIVING_LICENCE));
        mockHistoricSigningKeysExcept("drivingLicence");
        when(mockConfigService.getHistoricSigningKeys("drivingLicence"))
                .thenReturn(List.of(EC_PUBLIC_JWK_2, TEST_EC_PUBLIC_JWK));
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
        when(mockEvcsClientFactory.getClient()).thenReturn(mockEvcsClient);
        when(mockEvcsClient.getUserVcsForMigrationReconciliation("userId1"))
                .thenReturn(new EvcsGetUserVCsDto(List.of(evcsGetDtoOf(vc.getVcString()))));
        when(mockTacticalDataStore.getItems("userId1"))
                .thenReturn(List.of(vcStoreItemOf(vc.getVcString())));
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(any(), any()))
                .thenReturn(Optional.of(M1A));

        var request = new Request("vcs-with-p2-batch-id", List.of("userId1"), 4, true, true);

        var reconciliationReport = handler.handleRequest(request, mockContext);

        assertTrue(reconciliationReport.isCheckP2());
        assertEquals("vcs-with-p2-batch-id", reconciliationReport.getBatchId());
        assertEquals(1, reconciliationReport.getBatchSize());
        assertEquals(1, reconciliationReport.getIdentitiesFullyProcessed());
        assertEquals(1, reconciliationReport.getVcsMatchedCount());
        assertEquals(0, reconciliationReport.getVcsDifferentCount());
        assertEquals(1, reconciliationReport.getIdentityWithValidSignaturesCount());
        assertEquals(0, reconciliationReport.getIdentityWithInvalidSignaturesCount());
        assertEquals(0, reconciliationReport.getInvalidVcSignatureCount());
        assertEquals(1, reconciliationReport.getSuccessfullyAttainedP2Count());
        assertEquals(0, reconciliationReport.getFailedToAttainP2Count());
        assertTrue(reconciliationReport.isCheckSignatures());
    }

    @Test
    void handlerShouldHandleIdentityWithNonP2() throws Exception {
        var vc = vcDrivingPermit();
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
        when(mockEvcsClientFactory.getClient()).thenReturn(mockEvcsClient);
        when(mockEvcsClient.getUserVcsForMigrationReconciliation("userId1"))
                .thenReturn(new EvcsGetUserVCsDto(List.of(evcsGetDtoOf(vc.getVcString()))));
        when(mockTacticalDataStore.getItems("userId1"))
                .thenReturn(List.of(vcStoreItemOf(vc.getVcString())));
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(any(), any()))
                .thenReturn(Optional.empty());

        var request = new Request("vcs-non-p2-batch-id", List.of("userId1"), 4, false, true);

        var reconciliationReport = handler.handleRequest(request, mockContext);

        assertTrue(reconciliationReport.isCheckP2());
        assertEquals("vcs-non-p2-batch-id", reconciliationReport.getBatchId());
        assertEquals(1, reconciliationReport.getBatchSize());
        assertEquals(1, reconciliationReport.getIdentitiesFullyProcessed());
        assertEquals(1, reconciliationReport.getVcsMatchedCount());
        assertEquals(0, reconciliationReport.getVcsDifferentCount());
        assertEquals(0, reconciliationReport.getIdentityWithValidSignaturesCount());
        assertEquals(0, reconciliationReport.getIdentityWithInvalidSignaturesCount());
        assertEquals(0, reconciliationReport.getInvalidVcSignatureCount());
        assertEquals(0, reconciliationReport.getSuccessfullyAttainedP2Count());
        assertEquals(1, reconciliationReport.getFailedToAttainP2Count());
        assertFalse(reconciliationReport.isCheckSignatures());
    }

    @Test
    void handlerShouldHandleLambdaTimeout() throws Exception {
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
        when(mockEvcsClientFactory.getClient()).thenReturn(mockEvcsClient);
        when(mockEvcsClient.getUserVcsForMigrationReconciliation(any()))
                .thenReturn(new EvcsGetUserVCsDto(List.of()));
        when(mockTacticalDataStore.getItems(any())).thenReturn(List.of());

        when(mockContext.getRemainingTimeInMillis()).thenReturn(11_000).thenReturn(9_000);

        var request =
                new Request("timeout-batch-id", List.of("userId1", "userId2"), 4, false, false);

        var reconciliationReport = handler.handleRequest(request, mockContext);

        assertEquals("timeout-batch-id", reconciliationReport.getBatchId());
        assertEquals(2, reconciliationReport.getBatchSize());
        assertEquals(2, reconciliationReport.getIdentitiesFullyProcessed());
        assertEquals(2, reconciliationReport.getVcsMatchedCount());
        assertEquals(0, reconciliationReport.getVcsDifferentCount());
        assertEquals("Lambda close to timeout", reconciliationReport.getExitReason());
    }

    @Test
    void handlerShouldRefreshEvcsClientIfNeeded() throws Exception {
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
        when(mockEvcsClientFactory.getClient()).thenReturn(mockEvcsClient);
        when(mockEvcsClient.getUserVcsForMigrationReconciliation(any()))
                .thenReturn(new EvcsGetUserVCsDto(List.of()));
        when(mockTacticalDataStore.getItems(any())).thenReturn(List.of());
        when(mockContext.getRemainingTimeInMillis()).thenReturn(11_000);

        var lotsOfIds = IntStream.range(0, 9_100).mapToObj(i -> "userId").toList();

        var request = new Request("timeout-batch-id", lotsOfIds, 1, false, false);

        handler.handleRequest(request, mockContext);

        verify(mockEvcsClientFactory, times(2)).getClient();
    }

    @Test
    void handlerShouldSetExitReasonIfParallelExecutionFails() throws Exception {
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenReturn(mockForkJoinPool);
        when(mockForkJoinPool.submit(any(Runnable.class))).thenReturn(mockForkJoinTask);
        when(mockForkJoinTask.get())
                .thenThrow(new ExecutionException("Oops", new IllegalArgumentException()));

        var request =
                new Request("execution-failure-batch-id", List.of("userId1"), 4, false, false);

        var reconciliationReport = handler.handleRequest(request, mockContext);

        assertEquals(1, reconciliationReport.getBatchSize());
        assertEquals(0, reconciliationReport.getIdentitiesFullyProcessed());
        assertEquals("Parallel execution failed", reconciliationReport.getExitReason());
    }

    @Test
    void handlerShouldRecordEvcsReadFailures() throws Exception {
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
        when(mockEvcsClientFactory.getClient()).thenReturn(mockEvcsClient);
        when(mockEvcsClient.getUserVcsForMigrationReconciliation("userId1"))
                .thenThrow(new EvcsServiceException(418, FAILED_AT_EVCS_HTTP_REQUEST_SEND));

        var request = new Request("evcs-fail-batch-id", List.of("userId1"), 4, false, false);

        var reconciliationReport = handler.handleRequest(request, mockContext);

        assertEquals(1, reconciliationReport.getBatchSize());
        assertEquals(1, reconciliationReport.getIdentitiesFullyProcessed());
        assertEquals(1, reconciliationReport.getFailedEvcsReadCount());
        assertTrue(reconciliationReport.getFailedEvcsReadHashedUserIds().get(0).startsWith("15da"));
    }

    @Test
    void handlerShouldRecordTacticalReadFailures() throws Exception {
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
        when(mockEvcsClientFactory.getClient()).thenReturn(mockEvcsClient);
        when(mockEvcsClient.getUserVcsForMigrationReconciliation("userId1"))
                .thenReturn(new EvcsGetUserVCsDto(List.of()));
        when(mockTacticalDataStore.getItems("userId1")).thenThrow(new RuntimeException("Wat"));

        var request = new Request("evcs-fail-batch-id", List.of("userId1"), 4, false, false);

        var reconciliationReport = handler.handleRequest(request, mockContext);

        assertEquals(1, reconciliationReport.getBatchSize());
        assertEquals(1, reconciliationReport.getIdentitiesFullyProcessed());
        assertEquals(1, reconciliationReport.getFailedTacticalReadCount());
        assertTrue(
                reconciliationReport
                        .getFailedTacticalReadHashedUserIds()
                        .get(0)
                        .startsWith("15da"));
    }

    private EvcsGetUserVCDto evcsGetDtoOf(String vcString) {
        return new EvcsGetUserVCDto(
                vcString,
                CURRENT,
                Map.of("migrationV001", Map.of("metadata-batch-id", "timestamp")));
    }

    private VcStoreItem vcStoreItemOf(String vcString) {
        return VcStoreItem.builder()
                .credential(vcString)
                .credentialIssuer("drivingLicence")
                .build();
    }

    private void mockHistoricSigningKeysExcept(String... doNotMockCriId) {
        var doNotMockList = Arrays.asList(doNotMockCriId);
        for (var cri : Cri.values()) {
            if (doNotMockList.contains(cri.getId())) {
                continue;
            }
            when(mockConfigService.getHistoricSigningKeys(cri.getId()))
                    .thenThrow(new ConfigParameterNotFoundException(cri.getId()));
        }
    }
}
