package uk.gov.di.ipv.core.library.domain;

import lombok.Builder;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.time.Instant;
import java.util.List;

@Getter
@Builder(toBuilder = true)
@ExcludeFromGeneratedCoverageReport
public class ContraIndicator implements Comparable<ContraIndicator> {
    private final String code;
    private final Instant issuanceDate;
    private final String documentId;
    private final List<String> transactionIds;
    private final List<Mitigation> mitigations;
    private final List<Mitigation> incompleteMitigations;

    @Override
    public int compareTo(ContraIndicator other) {
        return this.issuanceDate.compareTo(other.issuanceDate);
    }
}
