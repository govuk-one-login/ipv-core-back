package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonDeserialize(using = SharedAttributesDeserializer.class)
public class SharedAttributes {
    private Name name;
    private String dateOfBirth;
    private Map<String, String> address;
    private List<Map<String, String>> addressHistory;

    private SharedAttributes() {}

    public SharedAttributes(
            Name name,
            String dateOfBirth,
            Map<String, String> address,
            List<Map<String, String>> addressHistory) {
        this.name = name;
        this.dateOfBirth = dateOfBirth;
        this.address = address;
        this.addressHistory = addressHistory;
    }

    public static SharedAttributes empty() {
        return new SharedAttributes();
    }

    public Optional<Name> getName() {
        return Optional.ofNullable(name);
    }

    public Optional<String> getDateOfBirth() {
        return Optional.ofNullable(dateOfBirth);
    }

    public Optional<Map<String, String>> getAddress() {
        return Optional.ofNullable(address);
    }

    public Optional<List<Map<String, String>>> getAddressHistory() {
        return Optional.ofNullable(addressHistory);
    }

    public static class Builder {

        private Name name;
        private String dateOfBirth;
        private Map<String, String> address;
        private List<Map<String, String>> addressHistory;

        public Builder setName(Name name) {
            this.name = name;
            return this;
        }

        public Builder setDateOfBirth(String dateOfBirth) {
            this.dateOfBirth = dateOfBirth;
            return this;
        }

        public Builder setAddress(Map<String, String> address) {
            this.address = address;
            return this;
        }

        public Builder setAddressHistory(List<Map<String, String>> addressHistory) {
            this.addressHistory = addressHistory;
            return this;
        }

        public SharedAttributes build() {
            return new SharedAttributes(name, dateOfBirth, address, addressHistory);
        }
    }
}
