package uk.gov.di.ipv.core.bulkmigratevcs.domain;

import lombok.Data;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
public class Report {
    private final Map<String, BatchSummary> batchSummaries;
    private int totalEvaluated;
    private int totalMigrated;
    private int totalSkipped;
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

    public void addBatchSummary(BatchSummary summary) {
        this.batchSummaries.put(summary.getBatchId(), summary);
    }

    public void setLastEvaluatedHashUserId(String lastEvaluatedHashUserId) {
        this.lastEvaluatedHashUserId = lastEvaluatedHashUserId;
    }

    public Report finalise() {
        batchSummaries
                .values()
                .forEach(
                        summary -> {
                            totalMigrated += summary.getMigrated();
                            totalSkipped += summary.getSkipped();
                            totalFailedTacticalRead += summary.getFailedTacticalRead();
                            totalFailedTacticalWrite += summary.getFailedTacticalWrite();
                            totalFailedEvcsWrite += summary.getFailedEvcsWrite();
                            totalEvaluated += summary.getTotal();

                            allFailedTacticalReadHashUserIds.addAll(
                                    summary.getFailedTacticalReadHashUserIds());
                            allFailedTacticalWriteHashUserIds.addAll(
                                    summary.getFailedTacticalWriteHashUserIds());
                            allFailedEvcsWriteHashUserIds.addAll(
                                    summary.getFailedEvcsWriteHashUserIds());
                        });

        return this;
    }
}
