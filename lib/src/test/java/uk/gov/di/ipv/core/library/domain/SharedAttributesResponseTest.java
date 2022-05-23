package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SharedAttributesResponseTest {

    @Test
    void shouldCreateSharedAttributesResponseFromListOfSharedAttributes() {

        Set<Name> nameSet = new HashSet<>();
        nameSet.add(new Name(List.of(new NameParts("Paul", "GivenName"))));

        Set<Address> addressSet = new HashSet<>();
        addressSet.add(
                new Address(
                        "PostalAddress",
                        "Lebsack Inc",
                        "758 Huel Neck",
                        "Hagenesstad",
                        "York",
                        "38421-3292",
                        "Tonga"));

        Set<BirthDate> birthDaySet = new HashSet<>();
        birthDaySet.add(new BirthDate("2020-02-03"));

        SharedAttributes sharedAttributes1 =
                new SharedAttributes.Builder()
                        .setName(nameSet)
                        .setAddress(addressSet)
                        .setBirthDate(birthDaySet)
                        .build();

        Set<Name> nameSet2 = new HashSet<>();
        nameSet2.add(new Name(List.of(new NameParts("Tony", "GivenName"))));

        Set<Address> addressSet2 = new HashSet<>();
        addressSet2.add(
                new Address(
                        "PostalAddress",
                        "Pensylvania",
                        "758 Huel Neck",
                        "Hagenesstad",
                        "Illinois",
                        "38421-3292",
                        "Tonga"));

        Set<BirthDate> birthDaySet2 = new HashSet<>();
        birthDaySet2.add(new BirthDate("2021-02-03"));
        SharedAttributes sharedAttributes2 =
                new SharedAttributes.Builder()
                        .setName(nameSet2)
                        .setAddress(addressSet2)
                        .setBirthDate(birthDaySet2)
                        .build();

        List<SharedAttributes> sharedAttributes = List.of(sharedAttributes1, sharedAttributes2);

        SharedAttributesResponse sharedAttributesResponse =
                SharedAttributesResponse.from(sharedAttributes);

        for (Address n : sharedAttributesResponse.getAddress()) {
            System.out.println(n.getAddressRegion());
            if (n.getAddressRegion().equals("Illinois")) {
                assertEquals("Illinois", n.getAddressRegion());
            }
            if (n.getAddressRegion().equals("York")) {
                assertEquals("York", n.getAddressRegion());
            }
        }
        assertEquals(2, sharedAttributesResponse.getName().size());
        assertEquals(2, sharedAttributesResponse.getAddress().size());
        assertEquals(2, sharedAttributesResponse.getBirthDate().size());
    }
}
