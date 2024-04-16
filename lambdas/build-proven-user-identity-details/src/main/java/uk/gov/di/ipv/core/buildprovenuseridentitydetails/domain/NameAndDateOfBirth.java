package uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public class NameAndDateOfBirth {
    private final String name;
    private final Map<String, String> formattedName;
    private final String dateOfBirth;

    public NameAndDateOfBirth(String name, Map<String, String> formattedName, String dateOfBirth) {
        this.name = name;
        this.formattedName = formattedName;
        this.dateOfBirth = dateOfBirth;
    }

    public String getName() {
        return name;
    }

    public Map<String, String> getFormattedName() {
        return formattedName;
    }

    public String getDateOfBirth() {
        return dateOfBirth;
    }
}
