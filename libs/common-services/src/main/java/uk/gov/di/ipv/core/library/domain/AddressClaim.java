package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class AddressClaim {
    private final List<Address> address;

    public AddressClaim(@JsonProperty(value = "address", required = true) List<Address> address) {
        this.address = address;
    }
}
