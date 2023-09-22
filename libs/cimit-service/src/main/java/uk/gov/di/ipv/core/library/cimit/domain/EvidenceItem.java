package uk.gov.di.ipv.core.library.cimit.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Getter
public class EvidenceItem {
    private String type;
    private List<ContraIndicator> contraIndicator;
}
