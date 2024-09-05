package uk.gov.di.ipv.core.bulkmigratevcs;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.enhanced.dynamodb.model.Page;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.EvcsMetadata;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.Request;
import uk.gov.di.ipv.core.library.client.EvcsClient;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.ScanDynamoDataStore;
import uk.gov.di.ipv.core.library.persistence.item.ReportUserIdentityItem;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_CONSTRUCT_EVCS_URI;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_UPDATE_IDENTITY;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.enums.EvcsVcProvenance.MIGRATED;

@ExtendWith(MockitoExtension.class)
class BulkMigrateVcsHandlerTest {

    public static final String HASH_USER_ID = "hashUserId";
    public static final String USER_ID = "userId";
    public static final String IDENTITY = "identity";
    @Captor private ArgumentCaptor<List<EvcsCreateUserVCsDto>> evcsCreateListCaptor;
    @Captor private ArgumentCaptor<List<VerifiableCredential>> vcListCaptor;
    @Mock private ScanDynamoDataStore<ReportUserIdentityItem> mockScanDataStore;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private EvcsClient mockEvcsClient;
    @Mock private PageIterable<ReportUserIdentityItem> mockPageIterable;
    @Mock private Page<ReportUserIdentityItem> mockPage;
    @Mock private Context mockContext;
    @Mock private VerifiableCredential migratedVc;
    @Mock private VerifiableCredential notMigratedVc;
    @InjectMocks BulkMigrateVcsHandler bulkMigrateVcsHandler;

    @Test
    void handlerShouldCorrectlyHandleMigrateAndSkip() throws Exception {
        var reportUserIdentityItems =
                List.of(
                        new ReportUserIdentityItem("id1", "P2", 3, List.of("vc"), false),
                        new ReportUserIdentityItem("id2", "P0", 1, List.of("vc"), false),
                        new ReportUserIdentityItem("id3", "P2", 3, List.of("vc"), false));

        mockScanResponse(null, List.of(reportUserIdentityItems), null);

        when(migratedVc.getMigrated()).thenReturn(Instant.now());
        when(notMigratedVc.getMigrated()).thenReturn(null);
        when(notMigratedVc.getVcString()).thenReturn("vcString");

        when(mockVerifiableCredentialService.getVcs("id1"))
                .thenReturn(List.of(migratedVc, migratedVc, notMigratedVc));

        when(mockVerifiableCredentialService.getVcs("id3"))
                .thenReturn(List.of(migratedVc, migratedVc, migratedVc));

        var report = bulkMigrateVcsHandler.handleRequest(new Request(null, 100, 0), mockContext);

        assertEquals(1, report.getTotalMigrated());
        assertEquals(2, report.getTotalSkipped());
        assertEquals(3, report.getTotalEvaluated());
        assertEquals(0, report.getTotalFailedEvcsWrite());
        assertEquals(0, report.getTotalFailedTacticalRead());
        assertEquals(0, report.getTotalFailedTacticalWrite());
        assertTrue(report.getAllFailedEvcsWriteHashUserIds().isEmpty());
        assertTrue(report.getAllFailedTacticalReadHashUserIds().isEmpty());
        assertTrue(report.getAllFailedTacticalWriteHashUserIds().isEmpty());
        assertEquals("Null - all batches complete", report.getLastEvaluatedHashUserId());

        verify(mockEvcsClient).storeUserVCs(eq("id1"), evcsCreateListCaptor.capture());

        var evcsCreateUserVCsDtoList = evcsCreateListCaptor.getValue();

        assertEquals(1, evcsCreateUserVCsDtoList.size());
        assertEquals("vcString", evcsCreateUserVCsDtoList.get(0).vc());
        assertEquals(CURRENT, evcsCreateUserVCsDtoList.get(0).state());
        assertEquals(MIGRATED, evcsCreateUserVCsDtoList.get(0).provenance());
        assertEquals(
                "START:3", ((EvcsMetadata) evcsCreateUserVCsDtoList.get(0).metadata()).batchId());
        assertTrue(
                Instant.parse(
                                ((EvcsMetadata) evcsCreateUserVCsDtoList.get(0).metadata())
                                        .timestamp())
                        .isAfter(Instant.now().minusSeconds(1)));

        verify(mockVerifiableCredentialService).updateIdentity(vcListCaptor.capture());

        var vcList = vcListCaptor.getValue();

        assertEquals(1, vcList.size());
        verify(vcList.get(0)).setMigrated(any(Instant.class));
    }

    @Test
    void handlerShouldCorrectlyHandleFailures() throws Exception {
        var reportUserIdentityItems =
                List.of(
                        new ReportUserIdentityItem("id1", "P2", 3, List.of("vc"), false),
                        new ReportUserIdentityItem("id2", "P2", 3, List.of("vc"), false),
                        new ReportUserIdentityItem("id3", "P2", 3, List.of("vc"), false));

        mockScanResponse(null, List.of(reportUserIdentityItems), null);

        when(notMigratedVc.getMigrated()).thenReturn(null);

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

        var report = bulkMigrateVcsHandler.handleRequest(new Request(null, 100, 1), mockContext);

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
    }

    @Test
    void handlerShouldCreateCorrectBatchIdForEachPage() {
        var reportUserIdentityItem =
                new ReportUserIdentityItem("id1", "P0", 3, List.of("vc"), false);
        var pageOne = List.of(reportUserIdentityItem);
        var pageTwo =
                List.of(reportUserIdentityItem, reportUserIdentityItem, reportUserIdentityItem);
        var pageThree = List.of(reportUserIdentityItem, reportUserIdentityItem);

        mockScanResponse(
                null,
                List.of(pageOne, pageTwo, pageThree),
                new ArrayList<>(Arrays.asList("hashOne", "hashTwo", null)));

        var report = bulkMigrateVcsHandler.handleRequest(new Request(null, 100, 1), mockContext);

        assertEquals(6, report.getTotalEvaluated());
        assertEquals(
                Set.of("START:1", "hashOne:3", "hashTwo:2"), report.getBatchSummaries().keySet());
    }

    @Test
    void handlerShouldStartScanAtProvidedHash() {
        var reportUserIdentityItem =
                new ReportUserIdentityItem("id1", "P0", 3, List.of("vc"), false);

        mockScanResponse("specificStartKey", List.of(List.of(reportUserIdentityItem)), null);

        var report =
                bulkMigrateVcsHandler.handleRequest(
                        new Request("specificStartKey", 100, 1), mockContext);

        assertEquals(1, report.getTotalEvaluated());
        assertEquals(Set.of("specificStartKey:1"), report.getBatchSummaries().keySet());
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

        var mockPageList = reportUserIdentityItemsList.stream().map(itemList -> mockPage).toList();
        when(mockPageIterable.iterator()).thenReturn(mockPageList.iterator());

        var pageCounts =
                reportUserIdentityItemsList.stream().map(List::size).collect(Collectors.toList());
        var pageCountOngoingStubbing = when(mockPage.count()).thenReturn(pageCounts.remove(0));
        for (var remainingCount : pageCounts) {
            pageCountOngoingStubbing.thenReturn(remainingCount);
        }

        var modifiableReportUserIdentityItemsList = new ArrayList<>(reportUserIdentityItemsList);
        var pageItemsOngoingStubbing =
                when(mockPage.items()).thenReturn(modifiableReportUserIdentityItemsList.remove(0));
        for (var remainingItemList : modifiableReportUserIdentityItemsList) {
            pageItemsOngoingStubbing.thenReturn(remainingItemList);
        }

        if (lastEvaluatedUserHashIds == null) {
            when(mockPage.lastEvaluatedKey())
                    .thenReturn(Map.of(HASH_USER_ID, AttributeValue.builder().s(null).build()));
        } else {
            var modifiableLastEvaluatedUserHashIds = new ArrayList<>(lastEvaluatedUserHashIds);
            var initialValue =
                    Map.of(
                            HASH_USER_ID,
                            AttributeValue.builder()
                                    .s(modifiableLastEvaluatedUserHashIds.remove(0))
                                    .build());
            var lastEvaluatedHashOngoingStubbing =
                    when(mockPage.lastEvaluatedKey())
                            .thenReturn(initialValue)
                            .thenReturn(initialValue); // method is called twice per page
            for (var remainingLastEvaluatedHash : modifiableLastEvaluatedUserHashIds) {
                var value =
                        remainingLastEvaluatedHash == null
                                ? null
                                : Map.of(
                                        HASH_USER_ID,
                                        AttributeValue.builder()
                                                .s(remainingLastEvaluatedHash)
                                                .build());
                lastEvaluatedHashOngoingStubbing.thenReturn(value).thenReturn(value);
            }
        }
        when(mockContext.getRemainingTimeInMillis()).thenReturn(100_000);
    }
}
