package uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.NameParts;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public record NameAndDateOfBirth(String name, List<NameParts> nameParts, String dateOfBirth) {}
