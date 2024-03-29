package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.EqualsAndHashCode;

import java.util.Optional;
import java.util.Set;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonPropertyOrder({"name", "birthDate", "address", "socialSecurityRecord"})
@JsonDeserialize(using = SharedClaimsDeserializer.class)
@EqualsAndHashCode
public class SharedClaims {
    private Set<Name> name;
    private Set<BirthDate> birthDate;
    private Set<Address> address;
    private Set<SocialSecurityRecord> socialSecurityRecord;

    private SharedClaims() {}

    public SharedClaims(
            Set<Name> name,
            Set<BirthDate> birthDate,
            Set<Address> address,
            Set<SocialSecurityRecord> socialSecurityRecord) {
        this.name = name;
        this.birthDate = birthDate;
        this.address = address;
        this.socialSecurityRecord = socialSecurityRecord;
    }

    public static SharedClaims empty() {
        return new SharedClaims();
    }

    public Optional<Set<Name>> getName() {
        return Optional.ofNullable(name);
    }

    public Optional<Set<BirthDate>> getBirthDate() {
        return Optional.ofNullable(birthDate);
    }

    public Optional<Set<Address>> getAddress() {
        return Optional.ofNullable(address);
    }

    public Optional<Set<SocialSecurityRecord>> getSocialSecurityRecord() {
        return Optional.ofNullable(socialSecurityRecord);
    }

    public void setName(Set<Name> name) {
        this.name = name;
    }

    public void setBirthDate(Set<BirthDate> birthDate) {
        this.birthDate = birthDate;
    }

    public void setAddress(Set<Address> address) {
        this.address = address;
    }

    public void setSocialSecurityRecord(Set<SocialSecurityRecord> socialSecurityRecord) {
        this.socialSecurityRecord = socialSecurityRecord;
    }

    public static class Builder {

        private Set<Name> name;
        private Set<BirthDate> birthDate;
        private Set<Address> address;
        private Set<SocialSecurityRecord> socialSecurityRecord;

        public Builder setBirthDate(Set<BirthDate> birthDate) {
            this.birthDate = birthDate;
            return this;
        }

        public Builder setAddress(Set<Address> address) {
            this.address = address;
            return this;
        }

        public Builder setName(Set<Name> name) {
            this.name = name;
            return this;
        }

        public Builder setSocialSecurityRecord(Set<SocialSecurityRecord> socialSecurityRecord) {
            this.socialSecurityRecord = socialSecurityRecord;
            return this;
        }

        public SharedClaims build() {
            return new SharedClaims(name, birthDate, address, socialSecurityRecord);
        }
    }
}
