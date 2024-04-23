package uk.gov.di.ipv.core.library.auditing.extension;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.Vot;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionVot(Vot vot) implements AuditExtensions {}
