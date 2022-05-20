package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.util.LinkedHashSet;
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

    public static SharedAttributesResponse from(Set<SharedAttributes> sharedAttributes) {
        Set<Name> nameSet = new LinkedHashSet<>();
        Set<BirthDate> birthDateSet = new LinkedHashSet<>();
        Set<Address> addressSet = new LinkedHashSet<>();

        sharedAttributes.forEach(
                sharedAttribute -> {
                    sharedAttribute.getName().ifPresent(nameSet::addAll);
                    sharedAttribute.getBirthDate().ifPresent(birthDateSet::addAll);
                    sharedAttribute.getAddress().ifPresent(addressSet::addAll);
                });

        return new SharedAttributesResponse(nameSet, birthDateSet, addressSet);
    }
}
