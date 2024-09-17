package uk.gov.di.ipv.core.library.auditing.extension;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionsEvcsFailedMigration(String batchId, Integer vcCount, String reason)
        implements AuditExtensions {}
