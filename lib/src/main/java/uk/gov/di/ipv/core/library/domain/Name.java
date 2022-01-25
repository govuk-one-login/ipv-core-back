package uk.gov.di.ipv.core.library.domain;

import java.util.List;

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
