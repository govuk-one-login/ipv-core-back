package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import uk.gov.di.model.BirthDate;
import uk.gov.di.model.Name;
import uk.gov.di.model.NamePart;

import java.util.List;

@Getter
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

    // Return the first name that we have (they should all be the same for now)
    // and concatenate all the name parts together into a single string.
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

    @JsonIgnore
    public List<NamePart> getNameParts() {
        return name.get(0).getNameParts();
    }
}
