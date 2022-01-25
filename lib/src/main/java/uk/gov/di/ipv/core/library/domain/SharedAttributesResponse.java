package uk.gov.di.ipv.core.library.domain;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class SharedAttributesResponse {

    private final Set<Name> names;
    private final Set<String> dateOfBirths;
    private final Set<Map<String, String>> addresses;
    private final Set<Map<String, String>> addressHistory;

    public SharedAttributesResponse(
            Set<Name> names,
            Set<String> dateOfBirths,
            Set<Map<String, String>> addresses,
            Set<Map<String, String>> addressHistory) {
        this.names = names;
        this.dateOfBirths = dateOfBirths;
        this.addresses = addresses;
        this.addressHistory = addressHistory;
    }

    public static SharedAttributesResponse from(List<SharedAttributes> sharedAttributes) {
        Set<Name> names = new HashSet<>();
        Set<String> dateOfBirths = new HashSet<>();
        Set<Map<String, String>> addresses = new HashSet<>();
        Set<Map<String, String>> addressHistory = new HashSet<>();
        sharedAttributes.forEach(
                sharedAttribute -> {
                    sharedAttribute.getName().map(names::add);
                    sharedAttribute.getDateOfBirth().map(dateOfBirths::add);
                    sharedAttribute.getAddress().map(addresses::add);
                    sharedAttribute.getAddressHistory().map(addressHistory::addAll);
                });

        return new SharedAttributesResponse(names, dateOfBirths, addresses, addressHistory);
    }

    public Set<Name> getNames() {
        return names;
    }

    public Set<String> getDateOfBirths() {
        return dateOfBirths;
    }

    public Set<Map<String, String>> getAddresses() {
        return addresses;
    }

    public Set<Map<String, String>> getAddressHistory() {
        return addressHistory;
    }
}
