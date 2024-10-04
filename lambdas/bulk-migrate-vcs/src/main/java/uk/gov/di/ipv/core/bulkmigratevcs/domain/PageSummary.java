package uk.gov.di.ipv.core.bulkmigratevcs.domain;

import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

@Getter
public class PageSummary {
    private final String exclusiveStartKey;
    private final int count;
    private int migrated;
    private int migratedVcs;
    private int skippedNonP2;
    private int skippedAlreadyMigrated;
    private int skippedPartiallyMigrated;
    private int skippedNoVcs;
    private int failedEvcsWrite;
    private int failedTacticalRead;
    private int failedTacticalWrite;
    private int failedTooManyBatchIds;
    private int total;
    private final List<String> failedEvcsWriteHashUserIds;
    private final List<String> failedTacticalReadHashUserIds;
    private final List<String> failedTacticalWriteHashUserIds;
    private final List<String> failedTooManyBatchIdsHashUserIds;

    public PageSummary(String exclusiveStartKey, int count) {
        this.exclusiveStartKey = exclusiveStartKey;
        this.count = count;
        this.failedEvcsWriteHashUserIds = new ArrayList<>();
        this.failedTacticalReadHashUserIds = new ArrayList<>();
        this.failedTacticalWriteHashUserIds = new ArrayList<>();
        this.failedTooManyBatchIdsHashUserIds = new ArrayList<>();
    }

    public String getExclusiveStartKey() {
        return exclusiveStartKey == null ? "null" : exclusiveStartKey;
    }

    public synchronized void incrementMigrated() {
        migrated++;
        total++;
    }

    public synchronized void incrementMigratedVcs(int migratedVcsCount) {
        migratedVcs += migratedVcsCount;
    }

    public synchronized void incrementSkippedNonP2() {
        skippedNonP2++;
        total++;
    }

    public synchronized void incrementSkippedAlreadyMigrated() {
        skippedAlreadyMigrated++;
        total++;
    }

    public synchronized void incrementSkippedPartiallyMigrated() {
        skippedPartiallyMigrated++;
        total++;
    }

    public synchronized void incrementSkippedNoVcs() {
        skippedNoVcs++;
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

    public synchronized void incrementFailedTooManyBatchIds(String hashUserId) {
        failedTooManyBatchIds++;
        total++;
        failedTooManyBatchIdsHashUserIds.add(hashUserId);
    }
}
