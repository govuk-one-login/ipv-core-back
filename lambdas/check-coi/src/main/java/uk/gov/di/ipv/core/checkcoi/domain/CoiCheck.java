package uk.gov.di.ipv.core.checkcoi.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;

@ExcludeFromGeneratedCoverageReport
public record CoiCheck(boolean isSuccessful, CoiCheckType type) {}
