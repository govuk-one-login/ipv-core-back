package uk.gov.di.ipv.core.bulkmigratevcs.domain;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
public class BatchReport {
    private final String batchId;
    private final List<PageSummary> pageSummaries;
    private int totalEvaluated;
    private int totalMigrated;
    private int totalMigratedVcs;
    private int totalSkippedNonP2;
    private int totalSkippedAlreadyMigrated;
    private int totalSkippedPartiallyMigrated;
    private int totalSkippedNoVcs;
    private int totalFailedTacticalRead;
    private int totalFailedTacticalWrite;
    private int totalFailedEvcsWrite;
    private int totalFailedTooManyBatchIds;
    private final List<String> allFailedTacticalReadHashUserIds;
    private final List<String> allFailedTacticalWriteHashUserIds;
    private final List<String> allFailedEvcsWriteHashUserIds;
    private final List<String> allFailedTooManyBatchIdsHashUserIds;
    @Setter private String nextBatchExclusiveStartKey;
    @Setter private String exitReason;

    public BatchReport(String batchId) {
        this.batchId = batchId;
        this.pageSummaries = new ArrayList<>();
        this.allFailedTacticalReadHashUserIds = new ArrayList<>();
        this.allFailedTacticalWriteHashUserIds = new ArrayList<>();
        this.allFailedEvcsWriteHashUserIds = new ArrayList<>();
        this.allFailedTooManyBatchIdsHashUserIds = new ArrayList<>();
    }

    public void addPageSummary(PageSummary summary) {
        totalMigrated += summary.getMigrated();
        totalMigratedVcs += summary.getMigratedVcs();
        totalSkippedNonP2 += summary.getSkippedNonP2();
        totalSkippedAlreadyMigrated += summary.getSkippedAlreadyMigrated();
        totalSkippedPartiallyMigrated += summary.getSkippedPartiallyMigrated();
        totalSkippedNoVcs += summary.getSkippedNoVcs();
        totalFailedTacticalRead += summary.getFailedTacticalRead();
        totalFailedTacticalWrite += summary.getFailedTacticalWrite();
        totalFailedEvcsWrite += summary.getFailedEvcsWrite();
        totalFailedTooManyBatchIds += summary.getFailedTooManyBatchIds();
        totalEvaluated += summary.getTotal();

        allFailedTacticalReadHashUserIds.addAll(summary.getFailedTacticalReadHashUserIds());
        allFailedTacticalWriteHashUserIds.addAll(summary.getFailedTacticalWriteHashUserIds());
        allFailedEvcsWriteHashUserIds.addAll(summary.getFailedEvcsWriteHashUserIds());
        allFailedTooManyBatchIdsHashUserIds.addAll(summary.getFailedTooManyBatchIdsHashUserIds());

        this.pageSummaries.add(summary);
    }
}
