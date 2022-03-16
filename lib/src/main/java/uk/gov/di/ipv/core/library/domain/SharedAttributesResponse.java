package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@JsonPropertyOrder({"name", "birthDate", "address"})
public class SharedAttributesResponse {

    private final Set<Name> name;
    private final Set<BirthDate> birthDate;
    private final Set<Address> address;

    public SharedAttributesResponse(
            Set<Name> name, Set<BirthDate> birthDate, Set<Address> address) {
        this.name = name;
        this.birthDate = birthDate;
        this.address = address;
    }

    public Set<Name> getName() {
        return name;
    }

    public Set<BirthDate> getBirthDate() {
        return birthDate;
    }

    public Set<Address> getAddress() {
        return address;
    }

    public static SharedAttributesResponse from(List<SharedAttributes> sharedAttributes) {
        Set<Name> name = new LinkedHashSet<>();
        Set<BirthDate> birthDate = new LinkedHashSet<>();
        Set<Address> address = new LinkedHashSet<>();

        sharedAttributes.forEach(
                sharedAttribute -> {
                    sharedAttribute.getName().ifPresent(name::addAll);
                    sharedAttribute.getBirthDate().ifPresent(birthDate::addAll);
                    sharedAttribute.getAddress().ifPresent(address::addAll);
                });

        return new SharedAttributesResponse(name, birthDate, address);
    }
}
