package uk.gov.di.ipv.core.library.domain;

import java.util.List;

public class Name {
    private final List<NameParts> nameParts;

    public Name(List<NameParts> nameParts) {
        this.nameParts = nameParts;
    }

    public List<NameParts> getNameParts() {
        return nameParts;
    }
}
