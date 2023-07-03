package uk.gov.di.ipv.core.library.domain;

import lombok.Builder;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.time.Instant;
import java.util.List;

@Getter
@Builder
@ExcludeFromGeneratedCoverageReport
public class ContraIndicator {
    private final String code;
    private final Instant issuanceDate;
    private final String documentId;
    private final List<String> transactionIds;
    private final List<Mitigation> mitigations;
    private final List<Mitigation> incompleteMitigations;
}
