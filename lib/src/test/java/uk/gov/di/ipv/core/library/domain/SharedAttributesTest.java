package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SharedAttributesTest {

    @Test
    void shouldBuildSharedAttributes() {
        List<NameParts> namePartsList = Arrays.asList(new NameParts("Paul", "GivenName"));
        Set<Name> nameSet = new HashSet<>();
        Name names = new Name(namePartsList);
        nameSet.add(names);

        Set<Address> addressSet = new HashSet<>();
        Address address =
                new Address(
                        "PostalAddress",
                        "Lebsack Inc",
                        "758 Huel Neck",
                        "Hagenesstad",
                        "Illinois",
                        "38421-3292",
                        "Tonga");
        addressSet.add(address);

        Set<BirthDate> birthDaySet = new HashSet<>();
        BirthDate birthDate = new BirthDate("2020-02-03");
        birthDaySet.add(birthDate);

        SharedAttributes response =
                new SharedAttributes.Builder()
                        .setName(nameSet)
                        .setAddress(addressSet)
                        .setBirthDate(birthDaySet)
                        .build();

        assertEquals(nameSet, response.getName().get());
        assertEquals(addressSet, response.getAddress().get());
        assertEquals(birthDaySet, response.getBirthDate().get());
    }

    @Test
    void shouldReturnEmptySharedAttributes() {
        assertEquals(Optional.empty(), SharedAttributes.empty().getName());
        assertEquals(Optional.empty(), SharedAttributes.empty().getAddress());
        assertEquals(Optional.empty(), SharedAttributes.empty().getBirthDate());
    }
}
