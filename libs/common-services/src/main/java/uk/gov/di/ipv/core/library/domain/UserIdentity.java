package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@ExcludeFromGeneratedCoverageReport
@Builder
public class UserIdentity {

    public static final String VCS_CLAIM_NAME = "https://vocab.account.gov.uk/v1/credentialJWT";
    public static final String ADDRESS_CLAIM_NAME = "https://vocab.account.gov.uk/v1/address";
    private static final String IDENTITY_CLAIM_NAME =
            "https://vocab.account.gov.uk/v1/coreIdentity";
    private static final String PASSPORT_CLAIM_NAME = "https://vocab.account.gov.uk/v1/passport";
    private static final String DRIVING_PERMIT_CLAIM_NAME =
            "https://vocab.account.gov.uk/v1/drivingPermit";
    private static final String NINO_CLAIM_NAME =
            "https://vocab.account.gov.uk/v1/socialSecurityRecord";
    public static final String EXIT_CODE_NAME = "exit_code";

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

    @JsonProperty(NINO_CLAIM_NAME)
    private JsonNode ninoClaim;

    @JsonProperty private String sub;

    @JsonProperty private String vot;

    @JsonProperty private String vtm;

    @JsonProperty(EXIT_CODE_NAME)
    private List<String> exitCode;

    @JsonCreator
    public UserIdentity(
            @JsonProperty(value = VCS_CLAIM_NAME, required = true) List<String> vcs,
            @JsonProperty(value = IDENTITY_CLAIM_NAME) IdentityClaim identityClaim,
            @JsonProperty(value = ADDRESS_CLAIM_NAME) JsonNode addressClaim,
            @JsonProperty(value = PASSPORT_CLAIM_NAME) JsonNode passportClaim,
            @JsonProperty(value = DRIVING_PERMIT_CLAIM_NAME) JsonNode drivingPermitClaim,
            @JsonProperty(value = NINO_CLAIM_NAME) JsonNode ninoClaim,
            @JsonProperty(value = "sub", required = true) String sub,
            @JsonProperty(value = "vot", required = true) String vot,
            @JsonProperty(value = "vtm", required = true) String vtm,
            @JsonProperty(value = EXIT_CODE_NAME) List<String> exitCode) {
        this.vcs = new ArrayList<>(vcs);
        this.identityClaim = identityClaim;
        this.addressClaim = addressClaim;
        this.passportClaim = passportClaim;
        this.drivingPermitClaim = drivingPermitClaim;
        this.ninoClaim = ninoClaim;
        this.sub = sub;
        this.vot = vot;
        this.vtm = vtm;
        this.exitCode = exitCode;
    }
}
