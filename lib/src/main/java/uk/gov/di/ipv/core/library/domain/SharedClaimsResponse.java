package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;

import java.util.LinkedHashSet;
import java.util.Set;

@JsonPropertyOrder({"name", "birthDate", "address", "email"})
public class SharedClaimsResponse {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Set<Name> name;
    private final Set<BirthDate> birthDate;
    private final Set<Address> address;
    private final String email;

    public SharedClaimsResponse(
            Set<Name> name, Set<BirthDate> birthDate, Set<Address> address, String email) {
        this.name = name;
        this.birthDate = birthDate;
        this.address = address;
        this.email = email;
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

    public String getEmail() {
        return email;
    }

    public static SharedClaimsResponse from(Set<SharedClaims> sharedAttributes, String email) {
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
                new StringMapMessage()
                        .with("sharedClaims", "built")
                        .with("names", nameSet.size())
                        .with("birthDates", birthDateSet.size())
                        .with("addresses", addressSet.size());
        LOGGER.info(message);

        return new SharedClaimsResponse(nameSet, birthDateSet, addressSet, email);
    }
}
