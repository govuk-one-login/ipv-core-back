package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;

import java.util.List;

@EqualsAndHashCode
public class IdentityClaim {
    private final List<Name> name;
    private final List<BirthDate> birthDate;

    public IdentityClaim(
            @JsonProperty(value = "name", required = true) List<Name> name,
            @JsonProperty(value = "birthDate", required = true) List<BirthDate> birthDate) {
        this.name = name;
        this.birthDate = birthDate;
    }

    public List<Name> getName() {
        return name;
    }

    public List<BirthDate> getBirthDate() {
        return birthDate;
    }

    // Concatenate the first name we have into a single string
    @JsonIgnore
    public String getFullName() {
        StringBuilder nameBuilder = new StringBuilder();
        name.get(0)
                .getNameParts()
                .forEach(
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
