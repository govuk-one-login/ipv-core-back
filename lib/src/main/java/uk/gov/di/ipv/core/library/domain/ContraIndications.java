package uk.gov.di.ipv.core.library.domain;

import lombok.Builder;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

@Getter
@Builder
@ExcludeFromGeneratedCoverageReport
public class ContraIndications {
    private final Map<String, ContraIndicator> contraIndicatorMap;
}
