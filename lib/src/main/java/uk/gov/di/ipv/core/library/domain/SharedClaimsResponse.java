package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.MapMessage;

import java.util.LinkedHashSet;
import java.util.Set;

@JsonPropertyOrder({"name", "birthDate", "address"})
public class SharedClaimsResponse {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Set<Name> name;
    private final Set<BirthDate> birthDate;
    private final Set<Address> address;

    public SharedClaimsResponse(Set<Name> name, Set<BirthDate> birthDate, Set<Address> address) {
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

    public static SharedClaimsResponse from(Set<SharedClaims> sharedAttributes) {
        Set<Name> nameSet = new LinkedHashSet<>();
        Set<BirthDate> birthDateSet = new LinkedHashSet<>();
        Set<Address> addressSet = new LinkedHashSet<>();

        sharedAttributes.forEach(
                sharedAttribute -> {
                    sharedAttribute.getName().ifPresent(nameSet::addAll);
                    sharedAttribute.getBirthDate().ifPresent(birthDateSet::addAll);
                    sharedAttribute.getAddress().ifPresent(addressSet::addAll);
                });

        var message =
                new MapMessage()
                        .with("sharedClaims", "built")
                        .with("names", nameSet.size())
                        .with("birthDates", birthDateSet.size())
                        .with("addresses", addressSet.size());
        LOGGER.info(message);

        return new SharedClaimsResponse(nameSet, birthDateSet, addressSet);
    }
}
