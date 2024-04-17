package uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.NameParts;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public class NameAndDateOfBirth {
    private final String name;
    private final List<NameParts> nameParts;
    private final String dateOfBirth;

    public NameAndDateOfBirth(String name, List<NameParts> nameParts, String dateOfBirth) {
        this.name = name;
        this.nameParts = nameParts;
        this.dateOfBirth = dateOfBirth;
    }

    public String getName() {
        return name;
    }

    public List<NameParts> getNameParts() {
        return nameParts;
    }

    public String getDateOfBirth() {
        return dateOfBirth;
    }
}
