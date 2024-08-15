package uk.gov.di.ipv.core.reportuseridentity.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
@ExcludeFromGeneratedCoverageReport
public record ReportProcessingResult(
        ReportSummary summary,
        Map<String, AttributeValue> tacticalStoreLastEvaluatedKey,
        Map<String, AttributeValue> userIdentitylastEvaluatedKey,
        Map<String, AttributeValue> buildReportLastEvaluatedKey) {}
