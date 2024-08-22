package uk.gov.di.ipv.core.reportuseridentity.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;
import java.util.Optional;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@ExcludeFromGeneratedCoverageReport
public class ReportProcessingResult {
    ReportSummary summary;
    Long tacticalVcsEvaluated;
    Map<String, Object> tacticalStoreLastEvaluatedKey;
    Long userIdentitiesEvaluated;
    Map<String, Object> userIdentitylastEvaluatedKey;
    Map<String, Object> buildReportLastEvaluatedKey;

    public void addTacticalVcsEvaluated(long count) {
        tacticalVcsEvaluated = Optional.ofNullable(tacticalVcsEvaluated).orElse(0L) + count;
    }

    public void addUserIdentitiesEvaluated(long count) {
        userIdentitiesEvaluated = Optional.ofNullable(userIdentitiesEvaluated).orElse(0L) + count;
    }
}
