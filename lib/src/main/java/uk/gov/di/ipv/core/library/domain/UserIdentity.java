package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@Getter
@Setter
@ExcludeFromGeneratedCoverageReport
@Builder
public class UserIdentity {

    public static final String VCS_CLAIM_NAME = "https://vocab.account.gov.uk/v1/credentialJWT";
    public static final String IDENTITY_CLAIM_NAME = "https://vocab.account.gov.uk/v1/coreIdentity";
    public static final String ADDRESS_CLAIM_NAME = "https://vocab.account.gov.uk/v1/address";
    public static final String PASSPORT_CLAIM_NAME = "https://vocab.account.gov.uk/v1/passport";

    @JsonProperty(VCS_CLAIM_NAME)
    private List<String> vcs;

    @JsonProperty(IDENTITY_CLAIM_NAME)
    private IdentityClaim identityClaim;

    @JsonProperty(ADDRESS_CLAIM_NAME)
    private JsonNode addressClaim;

    @JsonProperty(PASSPORT_CLAIM_NAME)
    private JsonNode passportClaim;

    @JsonProperty private String sub;

    @JsonProperty private String vot;

    @JsonProperty private String vtm;

    @JsonCreator
    public UserIdentity(
            @JsonProperty(value = VCS_CLAIM_NAME, required = true) List<String> vcs,
            @JsonProperty(value = IDENTITY_CLAIM_NAME) IdentityClaim identityClaim,
            @JsonProperty(value = ADDRESS_CLAIM_NAME) JsonNode addressClaim,
            @JsonProperty(value = PASSPORT_CLAIM_NAME) JsonNode passportClaim,
            @JsonProperty(value = "sub", required = true) String sub,
            @JsonProperty(value = "vot", required = true) String vot,
            @JsonProperty(value = "vtm", required = true) String vtm) {
        this.vcs = vcs;
        this.identityClaim = identityClaim;
        this.addressClaim = addressClaim;
        this.passportClaim = passportClaim;
        this.sub = sub;
        this.vot = vot;
        this.vtm = vtm;
    }
}
