package uk.gov.di.ipv.core.reportuseridentity.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@ExcludeFromGeneratedCoverageReport
public record ReportProcessingResult(
        ReportSummary summary,
        Map<String, Object> tacticalStoreLastEvaluatedKey,
        Map<String, Object> userIdentitylastEvaluatedKey,
        Map<String, Object> buildReportLastEvaluatedKey) {}
