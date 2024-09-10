package uk.gov.di.ipv.core.bulkmigratevcs.domain;

import lombok.Getter;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Getter
public class Report {
    private final Map<String, BatchSummary> batchSummaries;
    private int totalEvaluated;
    private int totalMigrated;
    private int totalSkippedNonP2;
    private int totalSkippedAlreadyMigrated;
    private int totalSkippedPartiallyMigrated;
    private int totalSkippedNoVcs;
    private int totalFailedTacticalRead;
    private int totalFailedTacticalWrite;
    private int totalFailedEvcsWrite;
    private final List<String> allFailedTacticalReadHashUserIds;
    private final List<String> allFailedTacticalWriteHashUserIds;
    private final List<String> allFailedEvcsWriteHashUserIds;
    private String lastEvaluatedHashUserId;

    public Report() {
        this.batchSummaries = new LinkedHashMap<>();
        this.allFailedTacticalReadHashUserIds = new ArrayList<>();
        this.allFailedTacticalWriteHashUserIds = new ArrayList<>();
        this.allFailedEvcsWriteHashUserIds = new ArrayList<>();
    }

    public synchronized void addBatchSummary(BatchSummary summary) {
        totalMigrated += summary.getMigrated();
        totalSkippedNonP2 += summary.getSkippedNonP2();
        totalSkippedAlreadyMigrated += summary.getSkippedAlreadyMigrated();
        totalSkippedPartiallyMigrated += summary.getSkippedPartiallyMigrated();
        totalSkippedNoVcs += summary.getSkippedNoVcs();
        totalFailedTacticalRead += summary.getFailedTacticalRead();
        totalFailedTacticalWrite += summary.getFailedTacticalWrite();
        totalFailedEvcsWrite += summary.getFailedEvcsWrite();
        totalEvaluated += summary.getTotal();

        allFailedTacticalReadHashUserIds.addAll(summary.getFailedTacticalReadHashUserIds());
        allFailedTacticalWriteHashUserIds.addAll(summary.getFailedTacticalWriteHashUserIds());
        allFailedEvcsWriteHashUserIds.addAll(summary.getFailedEvcsWriteHashUserIds());

        this.batchSummaries.put(summary.getBatchId(), summary);
    }

    public void setLastEvaluatedHashUserId(String lastEvaluatedHashUserId) {
        this.lastEvaluatedHashUserId = lastEvaluatedHashUserId;
    }
}
