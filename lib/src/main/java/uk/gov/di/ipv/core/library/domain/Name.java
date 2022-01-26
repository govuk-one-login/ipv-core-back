package uk.gov.di.ipv.core.library.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public class Name {

    private final List<String> givenNames;
    private final String familyName;

    public Name(List<String> givenNames, String familyName) {
        this.givenNames = givenNames;
        this.familyName = familyName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public List<String> getGivenNames() {
        return givenNames;
    }
}
