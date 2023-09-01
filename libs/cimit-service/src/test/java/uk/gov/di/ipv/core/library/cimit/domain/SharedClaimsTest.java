package uk.gov.di.ipv.core.library.cimit.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.domain.SharedClaims;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SharedClaimsTest {

    @Test
    void shouldBuildSharedAttributes() throws Exception {
        List<NameParts> namePartsList = Arrays.asList(new NameParts("Paul", "GivenName"));
        Set<Name> nameSet = new HashSet<>();
        Name names = new Name(namePartsList);
        nameSet.add(names);

        Set<Address> addressSet = new HashSet<>();
        addressSet.add(new ObjectMapper().readValue(TestFixtures.ADDRESS_JSON_1, Address.class));

        Set<BirthDate> birthDaySet = new HashSet<>();
        BirthDate birthDate = new BirthDate("2020-02-03");
        birthDaySet.add(birthDate);

        SharedClaims response =
                new SharedClaims.Builder()
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
        assertEquals(Optional.empty(), SharedClaims.empty().getName());
        assertEquals(Optional.empty(), SharedClaims.empty().getAddress());
        assertEquals(Optional.empty(), SharedClaims.empty().getBirthDate());
    }

    @Test
    void shouldOverrideAddressAttributes() throws JsonProcessingException {
        List<NameParts> namePartsList = Arrays.asList(new NameParts("Paul", "GivenName"));
        Set<Name> nameSet = new HashSet<>();
        Name names = new Name(namePartsList);
        nameSet.add(names);

        Set<Address> addressSet = new HashSet<>();
        addressSet.add(new ObjectMapper().readValue(TestFixtures.ADDRESS_JSON_1, Address.class));

        Set<BirthDate> birthDaySet = new HashSet<>();
        BirthDate birthDate = new BirthDate("2020-02-03");
        birthDaySet.add(birthDate);

        SharedClaims response =
                new SharedClaims.Builder()
                        .setName(nameSet)
                        .setAddress(addressSet)
                        .setBirthDate(birthDaySet)
                        .build();

        response.setAddress(null);

        assertEquals(nameSet, response.getName().get());
        assertEquals(Optional.empty(), response.getAddress());
        assertEquals(birthDaySet, response.getBirthDate().get());
    }
}
