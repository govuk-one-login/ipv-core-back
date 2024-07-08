package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonInclude;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.Vot;

import java.util.List;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionsVcEvidence<T>(
        String iss,
        List<T> evidence,
        @JsonInclude(NON_NULL) Boolean successful,
        @JsonInclude(NON_NULL) Vot vot,
        @JsonInclude(NON_NULL) Boolean isUkIssued,
        @JsonInclude(NON_NULL) Integer age)
        implements AuditExtensions {}
