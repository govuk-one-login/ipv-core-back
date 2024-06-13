package uk.gov.di.ipv.core.library.auditing.restricted;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.Name;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public record AuditRestrictedCheckCoi(
        List<Name> oldName,
        List<Name> newName,
        List<BirthDate> oldBirthDate,
        List<BirthDate> newBirthDate)
        implements AuditRestricted {}
