package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.ADDRESS_JSON_1;

class SharedClaimsTest {

    @Test
    void shouldBuildSharedAttributes() throws Exception {
        List<NameParts> namePartsList = Arrays.asList(new NameParts("Paul", "GivenName"));
        Set<Name> nameSet = new HashSet<>();
        Name names = new Name(namePartsList);
        nameSet.add(names);

        Set<Address> addressSet = new HashSet<>();
        addressSet.add(new ObjectMapper().readValue(ADDRESS_JSON_1, Address.class));

        Set<BirthDate> birthDaySet = new HashSet<>();
        BirthDate birthDate = new BirthDate("2020-02-03");
        birthDaySet.add(birthDate);

        SharedClaims response =
                SharedClaims.builder()
                        .name(nameSet)
                        .address(addressSet)
                        .birthDate(birthDaySet)
                        .build();

        assertEquals(nameSet, response.getName().get());
        assertEquals(addressSet, response.getAddress().get());
        assertEquals(birthDaySet, response.getBirthDate().get());
    }

    @Test
    void shouldReturnEmptySharedAttributes() {
        assertEquals(Optional.empty(), SharedClaims.empty().getName());
        assertEquals(Optional.empty(), SharedClaims.empty().getAddress());
        assertEquals(Optional.empty(), SharedClaims.empty().getBirthDate());
    }
}
