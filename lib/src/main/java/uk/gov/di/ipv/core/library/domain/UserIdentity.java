package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Getter;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@Getter
@Setter
@ExcludeFromGeneratedCoverageReport
public class UserIdentity {

    public static final String VCS_CLAIM_NAME = "https://vocab.account.gov.uk/v1/credentialJWT";
    public static final String IDENTITY_CLAIM_NAME = "https://vocab.account.gov.uk/v1/coreIdentity";
    public static final String ADDRESS_CLAIM_NAME = "https://vocab.account.gov.uk/v1/address";
    public static final String PASSPORT_CLAIM_NAME = "https://vocab.account.gov.uk/v1/passport";
    public static final String DRIVING_PERMIT_CLAIM_NAME =
            "https://vocab.account.gov.uk/v1/drivingPermit";

    @JsonProperty(VCS_CLAIM_NAME)
    private List<String> vcs;

    @JsonProperty(IDENTITY_CLAIM_NAME)
    private IdentityClaim identityClaim;

    @JsonProperty(ADDRESS_CLAIM_NAME)
    private JsonNode addressClaim;

    @JsonProperty(PASSPORT_CLAIM_NAME)
    private JsonNode passportClaim;

    @JsonProperty(DRIVING_PERMIT_CLAIM_NAME)
    private JsonNode drivingPermitClaim;

    @JsonProperty private String sub;

    @JsonProperty private String vot;

    @JsonProperty private String vtm;

    @JsonCreator
    public UserIdentity(
            @JsonProperty(value = VCS_CLAIM_NAME, required = true) List<String> vcs,
            @JsonProperty(value = IDENTITY_CLAIM_NAME) IdentityClaim identityClaim,
            @JsonProperty(value = ADDRESS_CLAIM_NAME) JsonNode addressClaim,
            @JsonProperty(value = PASSPORT_CLAIM_NAME) JsonNode passportClaim,
            @JsonProperty(value = DRIVING_PERMIT_CLAIM_NAME) JsonNode drivingPermitClaim,
            @JsonProperty(value = "sub", required = true) String sub,
            @JsonProperty(value = "vot", required = true) String vot,
            @JsonProperty(value = "vtm", required = true) String vtm) {
        this.vcs = vcs;
        this.identityClaim = identityClaim;
        this.addressClaim = addressClaim;
        this.passportClaim = passportClaim;
        this.drivingPermitClaim = drivingPermitClaim;
        this.sub = sub;
        this.vot = vot;
        this.vtm = vtm;
    }

    public static class Builder {
        private List<String> vcs;
        private IdentityClaim identityClaim;
        private JsonNode addressClaim;
        private JsonNode passportClaim;
        private JsonNode drivingPermitClaim;
        private String sub;
        private String vot;
        private String vtm;

        public Builder setVcs(List<String> vcs) {
            this.vcs = vcs;
            return this;
        }

        public Builder setIdentityClaim(IdentityClaim identityClaim) {
            this.identityClaim = identityClaim;
            return this;
        }

        public Builder setAddressClaim(JsonNode addressClaim) {
            this.addressClaim = addressClaim;
            return this;
        }

        public Builder setPassportClaim(JsonNode passportClaim) {
            this.passportClaim = passportClaim;
            return this;
        }

        public Builder setDrivingPermitClaim(JsonNode drivingPermitClaim) {
            this.drivingPermitClaim = drivingPermitClaim;
            return this;
        }

        public Builder setSub(String sub) {
            this.sub = sub;
            return this;
        }

        public Builder setVot(String vot) {
            this.vot = vot;
            return this;
        }

        public Builder setVtm(String vtm) {
            this.vtm = vtm;
            return this;
        }

        public UserIdentity build() {
            return new UserIdentity(
                    vcs,
                    identityClaim,
                    addressClaim,
                    passportClaim,
                    drivingPermitClaim,
                    sub,
                    vot,
                    vtm);
        }
    }
}
