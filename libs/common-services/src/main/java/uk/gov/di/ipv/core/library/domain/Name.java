package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
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

    // Concatenate all the name parts together into a single string.
    @JsonIgnore
    public String getFullName() {
        StringBuilder nameBuilder = new StringBuilder();
        nameParts.forEach(
                namePart -> {
                    if (nameBuilder.isEmpty()) {
                        nameBuilder.append(namePart.getValue());
                    } else {
                        nameBuilder.append(" ").append(namePart.getValue());
                    }
                });

        return nameBuilder.toString();
    }
}
