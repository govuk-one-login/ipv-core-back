package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class IdentityClaim {
    private final List<Name> name;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
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
}
