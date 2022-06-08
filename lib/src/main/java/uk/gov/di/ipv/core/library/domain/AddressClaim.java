package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode
public class AddressClaim {
    private final JsonNode address;

    public AddressClaim(@JsonProperty(value = "address", required = true) JsonNode address) {
        this.address = address;
    }

    public JsonNode getAddress() {
        return address;
    }
}
