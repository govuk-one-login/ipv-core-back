package uk.gov.di.ipv.core.reconcilemigratedvcs.domain;

import lombok.Getter;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;

import java.util.ArrayList;
import java.util.List;

@Getter
@ExcludeFromGeneratedCoverageReport
public class ReconciliationReport {
    private final String batchId;
    private final boolean checkSignatures;
    private final boolean checkP2;
    private final int batchSize;
    private int identitiesFullyProcessed;
    private int identitiesWithMatchingVcs;
    private int vcsMatchedCount;
    private int identitiesWithDifferentVcsCount;
    private int identityWithValidSignaturesCount;
    private int identityWithInvalidSignaturesCount;
    private int invalidVcSignatureCount;
    private int signatureValidationErrorCount;
    private int successfullyAttainedP2Count;
    private int failedToAttainP2Count;
    private int failedEvcsReadCount;
    private int failedTacticalReadCount;
    private int failedToParseEvcsVcsCount;
    @Setter private String exitReason;
    private final List<String> failedEvcsReadHashedUserIds = new ArrayList<>();
    private final List<String> failedTacticalReadHashedUserIds = new ArrayList<>();
    private final List<String> failedToParseEvcsVcsHashedUserIds = new ArrayList<>();
    private final List<String> signatureValidationErrorHashedUserIdAndSigs = new ArrayList<>();
    private final List<String> identityWithAnyInvalidSignaturesHashedUserIds = new ArrayList<>();
    private final List<String> invalidVcSignatureHashedUserIdAndCri = new ArrayList<>();
    private final List<String> failedToAttainP2HashedUserIds = new ArrayList<>();
    private final List<String> identitiesWithDifferentVcsHashedUserIds = new ArrayList<>();
    @Setter private List<String> unprocessedHashedUserIds = new ArrayList<>();

    public ReconciliationReport(Request request) {
        batchId = request.batchId();
        checkSignatures = request.checkSignatures();
        checkP2 = request.checkP2();
        batchSize = request.userIds().size();
    }

    public synchronized void incrementIdentitiesFullyProcessed() {
        identitiesFullyProcessed++;
    }

    public synchronized void incrementIdentitiesWithMatchingVcs(int vcCount) {
        identitiesWithMatchingVcs++;
        vcsMatchedCount += vcCount;
    }

    public synchronized void incrementIdentitiesWithDifferentVcs(String hashedUserId) {
        identitiesWithDifferentVcsCount++;
        identitiesWithDifferentVcsHashedUserIds.add(hashedUserId);
    }

    public synchronized void incrementFailedEvcsRead(String hashedUserId) {
        failedEvcsReadCount++;
        failedEvcsReadHashedUserIds.add(hashedUserId);
    }

    public synchronized void incrementFailedTacticalRead(String hashedUserId) {
        failedTacticalReadCount++;
        failedTacticalReadHashedUserIds.add(hashedUserId);
    }

    public synchronized void incrementFailedToParseEvcsVcs(String hashedUserId) {
        failedToParseEvcsVcsCount++;
        failedToParseEvcsVcsHashedUserIds.add(hashedUserId);
    }

    public synchronized void incrementIdentityWithValidSignatures() {
        identityWithValidSignaturesCount++;
    }

    public synchronized void incrementIdentityWithInvalidSignatures(String hashedUserId) {
        identityWithInvalidSignaturesCount++;
        identityWithAnyInvalidSignaturesHashedUserIds.add(hashedUserId);
    }

    public synchronized void incrementInvalidVcSignatureCount(
            String hashedUserId, VerifiableCredential vc) {
        invalidVcSignatureCount++;
        invalidVcSignatureHashedUserIdAndCri.add(
                String.format("%s - %s", hashedUserId, vc.getCri().getId()));
    }

    public synchronized void incrementSignatureValidationErrorCount(
            String hashedUserId, VerifiableCredential vc) {
        signatureValidationErrorCount++;
        signatureValidationErrorHashedUserIdAndSigs.add(
                String.format("%s%s", hashedUserId, vc.getSignedJwt().getSignature().toString()));
    }

    public synchronized void incrementFailedToAttainP2(String hashedUserId) {
        failedToAttainP2Count++;
        failedToParseEvcsVcsHashedUserIds.add(hashedUserId);
    }

    public synchronized void incrementSuccessfullyMatchedP2Count() {
        successfullyAttainedP2Count++;
    }
}
