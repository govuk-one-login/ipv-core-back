package uk.gov.di.ipv.core.bulkmigratevcs.domain;

import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

@Getter
public class BatchSummary {
    private final String batchId;
    private int migrated;
    private int skipped;
    private int failedEvcsWrite;
    private int failedTacticalRead;
    private int failedTacticalWrite;
    private int total;
    private final List<String> failedEvcsWriteHashUserIds;
    private final List<String> failedTacticalReadHashUserIds;
    private final List<String> failedTacticalWriteHashUserIds;

    public BatchSummary(String batchId) {
        this.batchId = batchId;
        this.failedEvcsWriteHashUserIds = new ArrayList<>();
        this.failedTacticalReadHashUserIds = new ArrayList<>();
        this.failedTacticalWriteHashUserIds = new ArrayList<>();
    }

    public synchronized void incrementMigrated() {
        migrated++;
        total++;
    }

    public synchronized void incrementSkipped() {
        skipped++;
        total++;
    }

    public synchronized void incrementFailedEvcsWrite(String hashUserId) {
        failedEvcsWrite++;
        total++;
        failedEvcsWriteHashUserIds.add(hashUserId);
    }

    public synchronized void incrementFailedTacticalRead(String hashUserId) {
        failedTacticalRead++;
        total++;
        failedTacticalReadHashUserIds.add(hashUserId);
    }

    public synchronized void incrementFailedTacticalWrite(String hashUserId) {
        failedTacticalWrite++;
        total++;
        failedTacticalWriteHashUserIds.add(hashUserId);
    }
}
