package uk.gov.di.ipv.core.library.auditing.extension;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionsEvcsMigration(List<String> credentialSignatures)
        implements AuditExtensions {}
