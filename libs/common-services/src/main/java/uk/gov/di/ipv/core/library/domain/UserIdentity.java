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

import static uk.gov.di.ipv.core.library.domain.VocabConstants.ADDRESS_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.DRIVING_PERMIT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.IDENTITY_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.NINO_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.PASSPORT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.RETURN_CODE_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VCS_CLAIM_NAME;

@Getter
@Setter
@ExcludeFromGeneratedCoverageReport
@Builder
public class UserIdentity {

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

    @JsonProperty(RETURN_CODE_NAME)
    private List<ReturnCode> returnCode;

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
            @JsonProperty(value = RETURN_CODE_NAME) List<ReturnCode> returnCode) {
        this.vcs = new ArrayList<>(vcs);
        this.identityClaim = identityClaim;
        this.addressClaim = addressClaim;
        this.passportClaim = passportClaim;
        this.drivingPermitClaim = drivingPermitClaim;
        this.ninoClaim = ninoClaim;
        this.sub = sub;
        this.vot = vot;
        this.vtm = vtm;
        this.returnCode = returnCode;
    }
}
