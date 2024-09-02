package uk.gov.di.ipv.core.reportuseridentity.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ReportProcessingRequest(
        boolean continueUniqueUserScan,
        boolean continueUserIdentityScan,
        boolean generateReport,
        Map<String, Object> tacticalStoreLastEvaluatedKey,
        Map<String, Object> userIdentitylastEvaluatedKey,
        Map<String, Object> buildReportLastEvaluatedKey,
        Integer pageSize,
        Integer parallelism) {}
