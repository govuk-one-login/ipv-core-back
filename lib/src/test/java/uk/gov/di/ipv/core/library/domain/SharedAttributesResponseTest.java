package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SharedAttributesResponseTest {

    @Test
    void shouldCreateSharedAttributesResponseFromListOfSharedAttributes() {
        Name name = new Name(List.of("Dan"), "Watson");
        Map<String, String> currentAddress = Map.of("line1", "test2");
        Map<String, String> oldAddress = Map.of("line1", "test2");
        String dateOfBirth = "2022-01-26";

        SharedAttributes sharedAttributes1 =
                new SharedAttributes.Builder()
                        .setName(name)
                        .setAddress(currentAddress)
                        .setAddressHistory(List.of(oldAddress))
                        .setDateOfBirth(dateOfBirth)
                        .build();

        SharedAttributes sharedAttributes2 =
                new SharedAttributes.Builder()
                        .setName(name)
                        .setAddress(currentAddress)
                        .setDateOfBirth(dateOfBirth)
                        .build();

        List<SharedAttributes> sharedAttributes = List.of(sharedAttributes1, sharedAttributes2);

        SharedAttributesResponse sharedAttributesResponse =
                SharedAttributesResponse.from(sharedAttributes);
        assertEquals(Set.of(name), sharedAttributesResponse.getNames());
        assertEquals(Set.of(currentAddress), sharedAttributesResponse.getAddresses());
        assertEquals(Set.of(oldAddress), sharedAttributesResponse.getAddressHistory());
        assertEquals(Set.of(dateOfBirth), sharedAttributesResponse.getDateOfBirths());
    }
}
