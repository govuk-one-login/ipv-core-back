package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.model.DrivingPermitDetails;
import uk.gov.di.model.PassportDetails;
import uk.gov.di.model.PostalAddress;
import uk.gov.di.model.SocialSecurityRecordDetails;

import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.ipv.core.library.domain.VocabConstants.ADDRESS_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.DRIVING_PERMIT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.IDENTITY_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.NINO_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.PASSPORT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.RETURN_CODE_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VCS_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;

@Getter
@Setter
@ExcludeFromGeneratedCoverageReport
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserIdentity extends UserClaims {

    @JsonProperty(VCS_CLAIM_NAME)
    private List<String> vcs;

    @JsonProperty private String sub;

    @JsonProperty private Vot vot;

    @JsonProperty private String vtm;

    @JsonProperty(RETURN_CODE_NAME)
    private List<ReturnCode> returnCode;

    @JsonCreator
    @Builder(builderMethodName = "UserIdentityBuilder")
    public UserIdentity(
            @JsonProperty(value = VCS_CLAIM_NAME, required = true) List<String> vcs,
            @JsonProperty(value = IDENTITY_CLAIM_NAME) IdentityClaim identityClaim,
            @JsonProperty(value = ADDRESS_CLAIM_NAME) List<PostalAddress> addressClaim,
            @JsonProperty(value = PASSPORT_CLAIM_NAME) List<PassportDetails> passportClaim,
            @JsonProperty(value = DRIVING_PERMIT_CLAIM_NAME)
                    List<DrivingPermitDetails> drivingPermitClaim,
            @JsonProperty(value = NINO_CLAIM_NAME) List<SocialSecurityRecordDetails> ninoClaim,
            @JsonProperty(value = "sub", required = true) String sub,
            @JsonProperty(value = VOT_CLAIM_NAME, required = true) Vot vot,
            @JsonProperty(value = "vtm", required = true) String vtm,
            @JsonProperty(value = RETURN_CODE_NAME) List<ReturnCode> returnCode) {
        super(identityClaim, addressClaim, passportClaim, drivingPermitClaim, ninoClaim);
        this.vcs = new ArrayList<>(vcs);
        this.sub = sub;
        this.vot = vot;
        this.vtm = vtm;
        this.returnCode = returnCode;
    }
}
