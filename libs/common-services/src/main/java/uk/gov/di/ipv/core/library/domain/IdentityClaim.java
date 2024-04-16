package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.util.List;
import java.util.Map;

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
    @JsonIgnore
    public String getFullName() {
        return name.get(0).getFullName();
    }

    @JsonIgnore
    public Map<String, String> getFormattedName() {
        return name.get(0).getFormattedName();
    }
}
