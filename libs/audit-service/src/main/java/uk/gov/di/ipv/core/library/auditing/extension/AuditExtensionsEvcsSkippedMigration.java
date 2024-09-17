package uk.gov.di.ipv.core.library.auditing.extension;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionsEvcsSkippedMigration(String batchId, String reason)
        implements AuditExtensions {}
