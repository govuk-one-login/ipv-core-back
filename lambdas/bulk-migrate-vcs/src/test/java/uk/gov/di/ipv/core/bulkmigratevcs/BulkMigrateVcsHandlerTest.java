package uk.gov.di.ipv.core.bulkmigratevcs;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import software.amazon.awssdk.enhanced.dynamodb.model.Page;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.Request;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.RequestBatchDetails;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.metadata.MigrationMetadata;
import uk.gov.di.ipv.core.bulkmigratevcs.factories.EvcsClientFactory;
import uk.gov.di.ipv.core.bulkmigratevcs.factories.ForkJoinPoolFactory;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsEvcsFailedMigration;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsEvcsSkippedMigration;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsEvcsSuccessfulMigration;
import uk.gov.di.ipv.core.library.client.EvcsClient;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.ScanDynamoDataStore;
import uk.gov.di.ipv.core.library.persistence.item.ReportUserIdentityItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BULK_MIGRATION_ROLLBACK_BATCHES;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_CONSTRUCT_EVCS_URI;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_UPDATE_IDENTITY;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.enums.EvcsVcProvenance.MIGRATED;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;

@ExtendWith(MockitoExtension.class)
class BulkMigrateVcsHandlerTest {

    public static final String HASH_USER_ID = "hashUserId";
    public static final String USER_ID = "userId";
    public static final String IDENTITY = "identity";
    public static final int TWO_MINUTES_IN_MS = 120_000;
    @Captor private ArgumentCaptor<List<EvcsCreateUserVCsDto>> evcsCreateListCaptor;
    @Captor private ArgumentCaptor<List<VerifiableCredential>> vcListCaptor;
    @Mock private ScanDynamoDataStore<ReportUserIdentityItem> mockScanDataStore;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private EvcsClientFactory mockEvcsClientFactory;
    @Mock private EvcsClient mockEvcsClient;
    @Mock private ForkJoinPoolFactory mockForkJoinPoolFactory;
    @Mock private ConfigService mockConfigService;
    @Mock private AuditService mockAuditService;
    @Mock private ForkJoinTask mockForkJoinTask;
    @Mock private ForkJoinPool mockForkJoinPool;
    @Mock private PageIterable<ReportUserIdentityItem> mockPageIterable;
    @Mock private Context mockContext;
    @Mock private VerifiableCredential migratedVc;
    @Mock private VerifiableCredential notMigratedVc;
    @Captor private ArgumentCaptor<AuditEvent> auditEventArgumentCaptor;
    @InjectMocks BulkMigrateVcsHandler bulkMigrateVcsHandler;

    @BeforeEach
    public void setup() {
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
        when(mockEvcsClientFactory.getClient()).thenReturn(mockEvcsClient);
    }

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(mockAuditService);
        auditInOrder.verify(mockAuditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

    @SuppressWarnings("java:S5961") // Too many assertions
    @Test
    void handlerShouldCorrectlyHandleMigrateAndSkip() throws Exception {
        var reportUserIdentityItems =
                List.of(
                        new ReportUserIdentityItem("migrate", "P2", 3, List.of("vc"), false),
                        new ReportUserIdentityItem("skipNonP2", "P0", 3, List.of("vc"), false),
                        new ReportUserIdentityItem("skipNoVcs", "P2", 0, List.of(), false),
                        new ReportUserIdentityItem(
                                "skipAlreadyMigrated", "P2", 3, List.of("vc"), false),
                        new ReportUserIdentityItem(
                                "skipPartiallyMigrated", "P2", 3, List.of("vc"), false));

        mockScanResponse(null, List.of(reportUserIdentityItems), Arrays.asList(new String[1]));

        when(migratedVc.getMigrated()).thenReturn(Instant.now());
        when(notMigratedVc.getMigrated()).thenReturn(null);
        when(notMigratedVc.getVcString())
                .thenReturn(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString());

        when(mockVerifiableCredentialService.getVcs("migrate"))
                .thenReturn(List.of(notMigratedVc, notMigratedVc, notMigratedVc));

        when(mockVerifiableCredentialService.getVcs("skipNoVcs")).thenReturn(List.of());

        when(mockVerifiableCredentialService.getVcs("skipAlreadyMigrated"))
                .thenReturn(List.of(migratedVc, migratedVc, migratedVc));

        when(mockVerifiableCredentialService.getVcs("skipPartiallyMigrated"))
                .thenReturn(List.of(migratedVc, migratedVc, notMigratedVc));
        when(mockConfigService.getParameter(COMPONENT_ID)).thenReturn("http://ipv/");

        var report =
                bulkMigrateVcsHandler.handleRequest(
                        new Request(new RequestBatchDetails("batchId", null, 2000), 100, null),
                        mockContext);

        assertEquals(1, report.getTotalMigrated());
        assertEquals(3, report.getTotalMigratedVcs());
        assertEquals(1, report.getTotalSkippedNoVcs());
        assertEquals(1, report.getTotalSkippedAlreadyMigrated());
        assertEquals(1, report.getTotalSkippedPartiallyMigrated());
        assertEquals(5, report.getTotalEvaluated());
        assertEquals(0, report.getTotalFailedEvcsWrite());
        assertEquals(0, report.getTotalFailedTacticalRead());
        assertEquals(0, report.getTotalFailedTacticalWrite());
        assertTrue(report.getAllFailedEvcsWriteHashUserIds().isEmpty());
        assertTrue(report.getAllFailedTacticalReadHashUserIds().isEmpty());
        assertTrue(report.getAllFailedTacticalWriteHashUserIds().isEmpty());
        assertEquals("null", report.getNextBatchExclusiveStartKey());
        assertEquals("Scan complete", report.getExitReason());

        verify(mockEvcsClient).storeUserVCs(eq("migrate"), evcsCreateListCaptor.capture());
        verify(mockAuditService, times(5)).sendAuditEvent(auditEventArgumentCaptor.capture());

        var evcsCreateUserVCsDtoList = evcsCreateListCaptor.getValue();

        assertEquals(3, evcsCreateUserVCsDtoList.size());
        assertEquals(
                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                evcsCreateUserVCsDtoList.get(0).vc());
        assertEquals(CURRENT, evcsCreateUserVCsDtoList.get(0).state());
        assertEquals(MIGRATED, evcsCreateUserVCsDtoList.get(0).provenance());
        assertEquals(
                "batchId",
                ((MigrationMetadata) evcsCreateUserVCsDtoList.get(0).metadata())
                        .migrationV001()
                        .batchId());
        assertTrue(
                Instant.parse(
                                ((MigrationMetadata) evcsCreateUserVCsDtoList.get(0).metadata())
                                        .migrationV001()
                                        .timestamp())
                        .isAfter(Instant.now().minusSeconds(1)));

        verify(mockVerifiableCredentialService).updateIdentity(vcListCaptor.capture());

        var vcList = vcListCaptor.getValue();

        assertEquals(3, vcList.size());
        verify(notMigratedVc, times(3)).setMigrated(any(Instant.class));
        verify(notMigratedVc, times(3)).setBatchId("batchId");
    }

    @Test
    void handlerShouldCorrectlyHandleFailures() throws Exception {
        var reportUserIdentityItems =
                List.of(
                        new ReportUserIdentityItem("id1", "P2", 3, List.of("vc"), false),
                        new ReportUserIdentityItem("id2", "P2", 3, List.of("vc"), false),
                        new ReportUserIdentityItem("id3", "P2", 3, List.of("vc"), false));

        mockScanResponse(null, List.of(reportUserIdentityItems), Arrays.asList(new String[1]));

        when(notMigratedVc.getMigrated()).thenReturn(null);
        when(mockConfigService.getParameter(COMPONENT_ID)).thenReturn("http://ipv/");

        when(mockVerifiableCredentialService.getVcs(any()))
                .thenThrow(new CredentialParseException("Boop"))
                .thenReturn(List.of(notMigratedVc))
                .thenReturn(List.of(notMigratedVc));
        doThrow(new EvcsServiceException(418, FAILED_TO_CONSTRUCT_EVCS_URI))
                .doNothing()
                .when(mockEvcsClient)
                .storeUserVCs(any(), any());
        doThrow(new VerifiableCredentialException(418, FAILED_TO_UPDATE_IDENTITY))
                .when(mockVerifiableCredentialService)
                .updateIdentity(any());

        var report =
                bulkMigrateVcsHandler.handleRequest(
                        new Request(new RequestBatchDetails("batchId", null, 2000), 100, 1),
                        mockContext);

        assertEquals(3, report.getTotalEvaluated());
        assertEquals(1, report.getTotalFailedTacticalRead());
        assertEquals(1, report.getTotalFailedEvcsWrite());
        assertEquals(1, report.getTotalFailedTacticalWrite());
        assertEquals(1, report.getAllFailedTacticalReadHashUserIds().size());
        assertTrue(report.getAllFailedTacticalReadHashUserIds().get(0).startsWith("b45"));
        assertEquals(1, report.getAllFailedEvcsWriteHashUserIds().size());
        assertTrue(report.getAllFailedEvcsWriteHashUserIds().get(0).startsWith("04b"));
        assertEquals(1, report.getAllFailedTacticalWriteHashUserIds().size());
        assertTrue(report.getAllFailedTacticalWriteHashUserIds().get(0).startsWith("f34"));
        verify(mockAuditService, times(3)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_EVCS_MIGRATION_FAILURE,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());
        assertEquals("id2", auditEventArgumentCaptor.getAllValues().get(0).getUser().getUserId());
        assertEquals(
                new AuditExtensionsEvcsFailedMigration(
                        "batchId", 0, "Failed to fetch VCs from tactical store"),
                auditEventArgumentCaptor.getAllValues().get(0).getExtensions());
    }

    @Test
    void handlerShouldCorrectlySendAuditEvents() throws Exception {
        var reportUserIdentityItems =
                List.of(
                        new ReportUserIdentityItem("migrate", "P2", 3, List.of("vc"), false),
                        new ReportUserIdentityItem("skipNonP2", "P0", 3, List.of("vc"), false));

        mockScanResponse(null, List.of(reportUserIdentityItems), Arrays.asList(new String[1]));

        when(notMigratedVc.getMigrated()).thenReturn(null);
        when(notMigratedVc.getVcString())
                .thenReturn(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString());

        when(mockVerifiableCredentialService.getVcs("migrate"))
                .thenReturn(List.of(notMigratedVc, notMigratedVc, notMigratedVc));
        when(mockConfigService.getParameter(COMPONENT_ID)).thenReturn("http://ipv/");

        bulkMigrateVcsHandler.handleRequest(
                new Request(new RequestBatchDetails("batchId", null, 2000), 100, 1), mockContext);

        verify(mockAuditService, times(2)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_EVCS_MIGRATION_SKIPPED,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());
        assertEquals(
                "skipNonP2", auditEventArgumentCaptor.getAllValues().get(0).getUser().getUserId());
        assertEquals(
                new AuditExtensionsEvcsSkippedMigration("batchId", "not_p2_identity"),
                auditEventArgumentCaptor.getAllValues().get(0).getExtensions());
        assertEquals(
                AuditEventTypes.IPV_EVCS_MIGRATION_SUCCESS,
                auditEventArgumentCaptor.getAllValues().get(1).getEventName());
        assertEquals(
                "migrate", auditEventArgumentCaptor.getAllValues().get(1).getUser().getUserId());
        var successfulMigrationEvent =
                (AuditExtensionsEvcsSuccessfulMigration)
                        auditEventArgumentCaptor.getAllValues().get(1).getExtensions();
        assertEquals("batchId", successfulMigrationEvent.batchId());
        assertEquals(3, successfulMigrationEvent.vcCount());
        assertEquals(3, successfulMigrationEvent.credentialSignatures().size());
    }

    @Test
    void handlerShouldStartBatchAtProvidedHash() {
        var reportUserIdentityItem =
                new ReportUserIdentityItem("id1", "P0", 3, List.of("vc"), false);

        mockScanResponse(
                "specificStartKey",
                List.of(List.of(reportUserIdentityItem)),
                Arrays.asList(new String[1]));

        var report =
                bulkMigrateVcsHandler.handleRequest(
                        new Request(
                                new RequestBatchDetails("batchId", "specificStartKey", 2000),
                                100,
                                1),
                        mockContext);

        assertEquals(1, report.getTotalEvaluated());
        assertEquals("specificStartKey", report.getPageSummaries().get(0).getExclusiveStartKey());
    }

    @MockitoSettings(strictness = LENIENT)
    @Test
    void handleRequestShouldExitIfAllItemsInBatchProcessed() {
        var item = new ReportUserIdentityItem("id1", "P0", 3, List.of("vc"), false);

        mockScanResponse(
                null,
                List.of(List.of(item), List.of(item), List.of(item), List.of(item), List.of(item)),
                List.of("hash1", "hash2", "hash3", "hash4"));

        var report =
                bulkMigrateVcsHandler.handleRequest(
                        new Request(new RequestBatchDetails("batchId", null, 4), 100, 1),
                        mockContext);

        assertEquals(4, report.getTotalEvaluated());
        assertEquals("hash4", report.getNextBatchExclusiveStartKey());
        assertEquals("All items in batch processed", report.getExitReason());
    }

    @MockitoSettings(strictness = LENIENT)
    @Test
    void handleRequestShouldExitIfLambdaTimeoutApproaching() {
        var item = new ReportUserIdentityItem("id1", "P0", 3, List.of("vc"), false);

        mockScanResponse(
                null,
                List.of(List.of(item), List.of(item), List.of(item), List.of(item), List.of(item)),
                List.of("hash1", "hash2", "hash3", "hash4"));

        when(mockContext.getRemainingTimeInMillis())
                .thenReturn(TWO_MINUTES_IN_MS)
                .thenReturn(TWO_MINUTES_IN_MS)
                .thenReturn(1);

        var report =
                bulkMigrateVcsHandler.handleRequest(
                        new Request(new RequestBatchDetails("batchId", null, 2000), 100, 1),
                        mockContext);

        assertEquals(3, report.getTotalEvaluated());
        assertEquals("hash3", report.getNextBatchExclusiveStartKey());
        assertEquals("Lambda close to timeout", report.getExitReason());
    }

    @MockitoSettings(strictness = LENIENT)
    @Test
    void handlerShouldContinueBatchIfParallelExecutionFailure() throws Exception {
        when(mockForkJoinPoolFactory.getForkJoinPool(1)).thenReturn(mockForkJoinPool);
        when(mockForkJoinPool.submit(any(Runnable.class))).thenReturn(mockForkJoinTask);
        when(mockForkJoinTask.get())
                .thenThrow(new ExecutionException("Oops", new IllegalArgumentException()));

        var reportItem = new ReportUserIdentityItem("id1", "22", 3, List.of("vc"), false);

        mockScanResponse(
                null,
                List.of(List.of(reportItem), List.of(reportItem, reportItem)),
                Arrays.asList("hash1", null));

        var report =
                bulkMigrateVcsHandler.handleRequest(
                        new Request(new RequestBatchDetails("batchId", null, 2000), 100, 1),
                        mockContext);

        assertEquals(2, report.getPageSummaries().size());
    }

    @Test
    void handlerShouldRefreshEvcsClientWhenApproachingLimit() {
        when(mockScanDataStore.scan(null, 100, HASH_USER_ID, USER_ID, IDENTITY))
                .thenReturn(mockPageIterable);
        when(mockContext.getRemainingTimeInMillis()).thenReturn(100_000);

        var mockPage = (Page<ReportUserIdentityItem>) mock(Page.class);
        when(mockPage.items()).thenReturn(List.of());
        when(mockPage.count())
                .thenReturn(9_000)
                .thenReturn(9_000)
                .thenReturn(9_010)
                .thenReturn(9_010)
                .thenReturn(18_001);
        when(mockPage.lastEvaluatedKey()).thenReturn(null);
        when(mockPageIterable.iterator())
                .thenReturn(List.of(mockPage, mockPage, mockPage).iterator());

        bulkMigrateVcsHandler.handleRequest(
                new Request(new RequestBatchDetails("batchId", null, 2000), 100, 1), mockContext);

        verify(mockEvcsClientFactory, times(3)).getClient();
    }

    @Nested
    class Rollbacks {
        @Test
        void handlerShouldRemigrateIdentityWithConfiguredRollbackBatchId() throws Exception {
            var reportUserIdentityItems =
                    List.of(new ReportUserIdentityItem("id1", "P2", 3, List.of("vc"), false));

            mockScanResponse(null, List.of(reportUserIdentityItems), Arrays.asList(new String[1]));

            when(migratedVc.getBatchId()).thenReturn("batch1");
            when(migratedVc.getMigrated()).thenReturn(Instant.now());
            when(migratedVc.getVcString())
                    .thenReturn(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString());

            when(mockVerifiableCredentialService.getVcs(any()))
                    .thenReturn(List.of(migratedVc, migratedVc, migratedVc));

            when(mockConfigService.getStringListParameter(BULK_MIGRATION_ROLLBACK_BATCHES))
                    .thenReturn(List.of("batch0", "batch1", "batch2"));

            var report =
                    bulkMigrateVcsHandler.handleRequest(
                            new Request(new RequestBatchDetails("batchId", null, 2000), 100, 1),
                            mockContext);

            assertEquals(1, report.getTotalEvaluated());
            assertEquals(1, report.getTotalMigrated());
            assertEquals(3, report.getTotalMigratedVcs());

            verify(mockAuditService).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(1, auditEventArgumentCaptor.getAllValues().size());
            var capturedAuditEvent = auditEventArgumentCaptor.getAllValues().get(0);
            assertEquals(
                    AuditEventTypes.IPV_EVCS_MIGRATION_SUCCESS, capturedAuditEvent.getEventName());
            assertEquals("id1", capturedAuditEvent.getUser().getUserId());
            assertEquals(
                    new AuditExtensionsEvcsSuccessfulMigration(
                            "batchId",
                            Collections.nCopies(
                                    3,
                                    PASSPORT_NON_DCMAW_SUCCESSFUL_VC
                                            .getSignedJwt()
                                            .getSignature()
                                            .toString()),
                            3),
                    capturedAuditEvent.getExtensions());
        }

        @Test
        void handlerShouldNotRemigrateIdentityIfBatchIdNotConfigured() throws Exception {
            var reportUserIdentityItems =
                    List.of(new ReportUserIdentityItem("id1", "P2", 3, List.of("vc"), false));

            mockScanResponse(null, List.of(reportUserIdentityItems), Arrays.asList(new String[1]));

            when(migratedVc.getBatchId()).thenReturn("batch3");
            when(migratedVc.getMigrated()).thenReturn(Instant.now());

            when(mockVerifiableCredentialService.getVcs(any()))
                    .thenReturn(List.of(migratedVc, migratedVc, migratedVc));

            when(mockConfigService.getStringListParameter(BULK_MIGRATION_ROLLBACK_BATCHES))
                    .thenReturn(List.of("batch0", "batch1", "batch2"));

            var report =
                    bulkMigrateVcsHandler.handleRequest(
                            new Request(new RequestBatchDetails("batchId", null, 2000), 100, 1),
                            mockContext);

            assertEquals(1, report.getTotalEvaluated());
            assertEquals(0, report.getTotalMigrated());
            assertEquals(0, report.getTotalMigratedVcs());

            verify(mockAuditService).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(1, auditEventArgumentCaptor.getAllValues().size());
            var capturedAuditEvent = auditEventArgumentCaptor.getAllValues().get(0);
            assertEquals(
                    AuditEventTypes.IPV_EVCS_MIGRATION_SKIPPED, capturedAuditEvent.getEventName());
            assertEquals("id1", capturedAuditEvent.getUser().getUserId());
            assertEquals(
                    new AuditExtensionsEvcsSkippedMigration("batchId", "already_migrated"),
                    capturedAuditEvent.getExtensions());
        }

        @Test
        void handlerShouldRecordFailureIfVcsHaveInconsistentBatchIds() throws Exception {
            var reportUserIdentityItems =
                    List.of(
                            new ReportUserIdentityItem("id1", "P2", 3, List.of("vc"), false),
                            new ReportUserIdentityItem("id1", "P2", 3, List.of("vc"), false),
                            new ReportUserIdentityItem("id2", "P2", 3, List.of("vc"), false));

            mockScanResponse(null, List.of(reportUserIdentityItems), Arrays.asList(new String[1]));

            when(migratedVc.getBatchId())
                    .thenReturn("batch1")
                    .thenReturn("batch2") // Non-matching case
                    .thenReturn("batch1")
                    .thenReturn(null); // Partial batch IDs case
            when(notMigratedVc.getMigrated()).thenReturn(null);
            when(notMigratedVc.getVcString())
                    .thenReturn(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString());

            when(mockVerifiableCredentialService.getVcs(any()))
                    .thenReturn(List.of(migratedVc, migratedVc))
                    .thenReturn(List.of(migratedVc, migratedVc))
                    .thenReturn(List.of(notMigratedVc));

            var report =
                    bulkMigrateVcsHandler.handleRequest(
                            new Request(new RequestBatchDetails("batchId", null, 2000), 100, 1),
                            mockContext);

            assertEquals(3, report.getTotalEvaluated());
            assertEquals(2, report.getTotalFailedTooManyBatchIds());
            assertEquals(1, report.getTotalMigrated());
            assertEquals(1, report.getTotalMigratedVcs());
            assertEquals(2, report.getAllFailedTooManyBatchIdsHashUserIds().size());
            assertTrue(report.getAllFailedTooManyBatchIdsHashUserIds().get(0).startsWith("f34"));
            assertTrue(report.getAllFailedTooManyBatchIdsHashUserIds().get(1).startsWith("b45"));

            verify(mockAuditService, times(3)).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(3, auditEventArgumentCaptor.getAllValues().size());

            var capturedAuditEventOne = auditEventArgumentCaptor.getAllValues().get(2);
            assertEquals(
                    AuditEventTypes.IPV_EVCS_MIGRATION_SUCCESS,
                    capturedAuditEventOne.getEventName());
            assertEquals("id1", capturedAuditEventOne.getUser().getUserId());
            assertEquals(
                    new AuditExtensionsEvcsSuccessfulMigration(
                            "batchId",
                            List.of(
                                    PASSPORT_NON_DCMAW_SUCCESSFUL_VC
                                            .getSignedJwt()
                                            .getSignature()
                                            .toString()),
                            1),
                    capturedAuditEventOne.getExtensions());

            var capturedAuditEventTwo = auditEventArgumentCaptor.getAllValues().get(1);
            assertEquals(
                    AuditEventTypes.IPV_EVCS_MIGRATION_FAILURE,
                    capturedAuditEventTwo.getEventName());
            assertEquals("id2", capturedAuditEventTwo.getUser().getUserId());
            assertEquals(
                    new AuditExtensionsEvcsFailedMigration(
                            "batchId", 2, "Too many batch IDs in tactical VCs"),
                    capturedAuditEventTwo.getExtensions());

            var capturedAuditEventThree = auditEventArgumentCaptor.getAllValues().get(0);
            assertEquals(
                    AuditEventTypes.IPV_EVCS_MIGRATION_FAILURE,
                    capturedAuditEventThree.getEventName());
            assertEquals("id1", capturedAuditEventThree.getUser().getUserId());
            assertEquals(
                    new AuditExtensionsEvcsFailedMigration(
                            "batchId", 2, "Too many batch IDs in tactical VCs"),
                    capturedAuditEventThree.getExtensions());
        }
    }

    private void mockScanResponse(
            String exclusiveStartUserHashId,
            List<List<ReportUserIdentityItem>> reportUserIdentityItemsList,
            List<String> lastEvaluatedUserHashIds) {
        when(mockScanDataStore.scan(
                        exclusiveStartUserHashId == null
                                ? null
                                : Map.of(
                                        HASH_USER_ID,
                                        AttributeValue.builder()
                                                .s(exclusiveStartUserHashId)
                                                .build()),
                        100,
                        HASH_USER_ID,
                        USER_ID,
                        IDENTITY))
                .thenReturn(mockPageIterable);

        var mockPageList =
                reportUserIdentityItemsList.stream()
                        .map(
                                itemList -> {
                                    var mockPage = (Page<ReportUserIdentityItem>) mock(Page.class);
                                    when(mockPage.items()).thenReturn(itemList);
                                    when(mockPage.count()).thenReturn(itemList.size());
                                    return mockPage;
                                })
                        .toList();

        for (var i = 0; i < lastEvaluatedUserHashIds.size(); i++) {
            when(mockPageList.get(i).lastEvaluatedKey())
                    .thenReturn(
                            lastEvaluatedUserHashIds.get(i) == null
                                    ? null
                                    : Map.of(
                                            HASH_USER_ID,
                                            AttributeValue.builder()
                                                    .s(lastEvaluatedUserHashIds.get(i))
                                                    .build()));
        }

        when(mockPageIterable.iterator()).thenReturn(mockPageList.iterator());
        when(mockContext.getRemainingTimeInMillis()).thenReturn(100_000);
    }
}
