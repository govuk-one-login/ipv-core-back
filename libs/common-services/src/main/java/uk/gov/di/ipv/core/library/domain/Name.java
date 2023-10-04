package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;

import java.util.List;

@EqualsAndHashCode
public class Name {
    private final List<NameParts> nameParts;

    public Name(@JsonProperty(value = "nameParts", required = true) List<NameParts> nameParts) {
        this.nameParts = nameParts;
    }

    public List<NameParts> getNameParts() {
        return nameParts;
    }
}
