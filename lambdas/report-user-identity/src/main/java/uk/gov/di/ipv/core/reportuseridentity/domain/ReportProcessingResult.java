package uk.gov.di.ipv.core.reportuseridentity.domain;

import lombok.Builder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Builder
@ExcludeFromGeneratedCoverageReport
public record ReportProcessingResult(ReportSummary summary) {}
