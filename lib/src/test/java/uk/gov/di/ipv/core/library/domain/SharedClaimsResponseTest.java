package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.ADDRESS_JSON_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.ADDRESS_JSON_2;

class SharedClaimsResponseTest {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void shouldCreateSharedAttributesResponseFromListOfSharedAttributes() throws Exception {

        Set<Name> nameSet = new HashSet<>();
        nameSet.add(new Name(List.of(new NameParts("Paul", "GivenName"))));

        Set<Address> addressSet = new HashSet<>();
        addressSet.add(objectMapper.readValue(ADDRESS_JSON_1, Address.class));

        Set<BirthDate> birthDaySet = new HashSet<>();
        birthDaySet.add(new BirthDate("2020-02-03"));

        SharedClaims sharedClaims1 =
                SharedClaims.builder()
                        .name(nameSet)
                        .address(addressSet)
                        .birthDate(birthDaySet)
                        .build();

        Set<Name> nameSet2 = new HashSet<>();
        nameSet2.add(new Name(List.of(new NameParts("Tony", "GivenName"))));

        Set<Address> addressSet2 = new HashSet<>();
        addressSet2.add(objectMapper.readValue(ADDRESS_JSON_2, Address.class));

        Set<BirthDate> birthDaySet2 = new HashSet<>();
        birthDaySet2.add(new BirthDate("2021-02-03"));
        SharedClaims sharedClaims2 =
                SharedClaims.builder()
                        .name(nameSet2)
                        .address(addressSet2)
                        .birthDate(birthDaySet2)
                        .build();

        Set<SharedClaims> sharedAttributes = Set.of(sharedClaims1, sharedClaims2);

        SharedClaimsResponse sharedClaimsResponse = SharedClaimsResponse.from(sharedAttributes);

        assertEquals(2, sharedClaimsResponse.getName().size());
        assertEquals(2, sharedClaimsResponse.getAddress().size());
        assertEquals(2, sharedClaimsResponse.getBirthDate().size());
    }
}
