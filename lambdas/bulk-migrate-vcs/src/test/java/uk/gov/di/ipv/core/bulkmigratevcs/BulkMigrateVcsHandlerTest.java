package uk.gov.di.ipv.core.bulkmigratevcs;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import software.amazon.awssdk.enhanced.dynamodb.model.Page;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.EvcsMetadata;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.Request;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.RequestBatchDetails;
import uk.gov.di.ipv.core.bulkmigratevcs.factories.ForkJoinPoolFactory;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
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
import static org.mockito.Mockito.*;
import static org.mockito.quality.Strictness.LENIENT;
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
    @Mock private EvcsClient mockEvcsClient;
    @Mock private ForkJoinPoolFactory mockForkJoinPoolFactory;
    @Mock private ForkJoinTask mockForkJoinTask;
    @Mock private ForkJoinPool mockForkJoinPool;
    @Mock private PageIterable<ReportUserIdentityItem> mockPageIterable;
    @Mock private Context mockContext;
    @Mock private VerifiableCredential migratedVc;
    @Mock private VerifiableCredential notMigratedVc = PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
    @Mock private ConfigService configService;
    @Mock private AuditService auditService;
    @Captor private ArgumentCaptor<AuditEvent> auditEventArgumentCaptor;
    @InjectMocks BulkMigrateVcsHandler bulkMigrateVcsHandler;

    @BeforeEach
    public void setup() {
        when(mockForkJoinPoolFactory.getForkJoinPool(anyInt())).thenCallRealMethod();
    }

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(auditService);
        auditInOrder.verify(auditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

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
        when(notMigratedVc.getVcString()).thenReturn(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.toString());

        when(mockVerifiableCredentialService.getVcs("migrate"))
                .thenReturn(List.of(notMigratedVc, notMigratedVc, notMigratedVc));

        when(mockVerifiableCredentialService.getVcs("skipNoVcs")).thenReturn(List.of());

        when(mockVerifiableCredentialService.getVcs("skipAlreadyMigrated"))
                .thenReturn(List.of(migratedVc, migratedVc, migratedVc));

        when(mockVerifiableCredentialService.getVcs("skipPartiallyMigrated"))
                .thenReturn(List.of(migratedVc, migratedVc, notMigratedVc));
        when(configService.getParameter(COMPONENT_ID)).thenReturn("http://ipv/");

        var report =
                bulkMigrateVcsHandler.handleRequest(
                        new Request(new RequestBatchDetails("batchId", null, 2000), 100, null),
                        mockContext);

        assertEquals(1, report.getTotalMigrated());
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
        verify(auditService, times(5)).sendAuditEvent(auditEventArgumentCaptor.capture());

        var evcsCreateUserVCsDtoList = evcsCreateListCaptor.getValue();

        assertEquals(3, evcsCreateUserVCsDtoList.size());
        assertEquals(
                PASSPORT_NON_DCMAW_SUCCESSFUL_VC.toString(), evcsCreateUserVCsDtoList.get(0).vc());
        assertEquals(CURRENT, evcsCreateUserVCsDtoList.get(0).state());
        assertEquals(MIGRATED, evcsCreateUserVCsDtoList.get(0).provenance());
        assertEquals(
                "batchId", ((EvcsMetadata) evcsCreateUserVCsDtoList.get(0).metadata()).batchId());
        assertTrue(
                Instant.parse(
                                ((EvcsMetadata) evcsCreateUserVCsDtoList.get(0).metadata())
                                        .timestamp())
                        .isAfter(Instant.now().minusSeconds(1)));

        verify(mockVerifiableCredentialService).updateIdentity(vcListCaptor.capture());

        var vcList = vcListCaptor.getValue();

        assertEquals(3, vcList.size());
        verify(vcList.get(0), times(3)).setMigrated(any(Instant.class));
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
        when(configService.getParameter(COMPONENT_ID)).thenReturn("http://ipv/");

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
        verify(auditService, times(3)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_EVCS_MIGRATION_FAILURE,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());
    }

    @Test
    void handlerShouldCorrectlySendAuditEvents() throws Exception {
        var reportUserIdentityItems =
                List.of(
                        new ReportUserIdentityItem("migrate", "P2", 3, List.of("vc"), false),
                        new ReportUserIdentityItem("skipNonP2", "P0", 3, List.of("vc"), false));

        mockScanResponse(null, List.of(reportUserIdentityItems), Arrays.asList(new String[1]));

        when(notMigratedVc.getMigrated()).thenReturn(null);
        when(notMigratedVc.getVcString()).thenReturn(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.toString());

        when(mockVerifiableCredentialService.getVcs("migrate"))
                .thenReturn(List.of(notMigratedVc, notMigratedVc, notMigratedVc));
        when(configService.getParameter(COMPONENT_ID)).thenReturn("http://ipv/");

        bulkMigrateVcsHandler.handleRequest(
                new Request(new RequestBatchDetails("batchId", null, 2000), 100, 1), mockContext);

        verify(auditService, times(2)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_EVCS_MIGRATION_SKIPPED,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());
        assertEquals(
                AuditEventTypes.IPV_EVCS_MIGRATION_SUCCESS,
                auditEventArgumentCaptor.getAllValues().get(1).getEventName());
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
