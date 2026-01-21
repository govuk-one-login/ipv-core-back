package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionExpiredFraudVcFound(
        @JsonProperty(value = "vc_expiry_period_ms", required = true) Long vcExpiryPeriodMs,
        @JsonProperty(value = "vc_issue_date", required = true) Long vcIssueDate)
        implements AuditExtensions {}
