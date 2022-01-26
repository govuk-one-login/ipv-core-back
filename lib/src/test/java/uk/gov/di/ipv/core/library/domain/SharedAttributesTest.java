package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SharedAttributesTest {

    @Test
    void shouldBuildSharedAttributes() {
        Name name = new Name(List.of("Dan"), "Watson");
        Map<String, String> address = Map.of("line1", "test");
        List<Map<String, String>> addressHistory = List.of(address);
        String dateOfBirth = "2022-01-26";

        SharedAttributes response =
                new SharedAttributes.Builder()
                        .setName(name)
                        .setAddress(address)
                        .setAddressHistory(addressHistory)
                        .setDateOfBirth(dateOfBirth)
                        .build();

        assertEquals(name, response.getName().get());
        assertEquals(address, response.getAddress().get());
        assertEquals(addressHistory, response.getAddressHistory().get());
        assertEquals(dateOfBirth, response.getDateOfBirth().get());
    }

    @Test
    void shouldReturnEmptySharedAttributes() {
        assertEquals(Optional.empty(), SharedAttributes.empty().getName());
        assertEquals(Optional.empty(), SharedAttributes.empty().getAddress());
        assertEquals(Optional.empty(), SharedAttributes.empty().getAddressHistory());
        assertEquals(Optional.empty(), SharedAttributes.empty().getDateOfBirth());
    }
}
