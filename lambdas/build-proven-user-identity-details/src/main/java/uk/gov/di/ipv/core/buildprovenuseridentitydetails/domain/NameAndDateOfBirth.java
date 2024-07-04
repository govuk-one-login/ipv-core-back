package uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.model.NamePart;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public record NameAndDateOfBirth(String name, List<NamePart> nameParts, String dateOfBirth) {}
