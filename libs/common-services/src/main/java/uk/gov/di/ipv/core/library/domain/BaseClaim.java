package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

// Base class for claims that need to be serialised by the Nimbus JWT library.
public abstract class BaseClaim {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // The JSON serialiser used by the Nimbus JWT library includes null values within claims which
    // we don't want. So we need to have a way of giving the library the claim values without
    // including nulls.
    public Map<String, Object> toMapWithNoNulls() {
        try {
            var jsonString = OBJECT_MAPPER.writeValueAsString(this);
            return OBJECT_MAPPER.readValue(jsonString, new TypeReference<>() {});
        } catch (JsonProcessingException e) {
            // This should never happen and would indicate a coding error, so we convert to a
            // runtime exception
            throw new IllegalArgumentException("Error converting object to map", e);
        }
    }
}
