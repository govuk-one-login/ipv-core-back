package uk.gov.di.ipv.core.library.sis.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.UserClaims;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.model.DrivingPermitDetails;
import uk.gov.di.model.PassportDetails;
import uk.gov.di.model.PostalAddress;
import uk.gov.di.model.SocialSecurityRecordDetails;

import java.util.List;

import static uk.gov.di.ipv.core.library.domain.VocabConstants.ADDRESS_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.DRIVING_PERMIT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.IDENTITY_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.NINO_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.PASSPORT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VCS_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;

@Getter
@JsonIgnoreProperties(ignoreUnknown = true)
public class SisStoredIdentityContent extends UserClaims {
    @NonNull
    @JsonProperty(value = "credentials")
    private List<String> credentialSignatures;

    @JsonProperty(VCS_CLAIM_NAME)
    private List<String> vcs;

    @JsonProperty private String sub;

    @NonNull @JsonProperty private Vot vot;

    @JsonProperty private String vtm;

    @JsonCreator
    @Builder(builderMethodName = "UserIdentityBuilder")
    public SisStoredIdentityContent(
            @JsonProperty(value = "sub", required = true) String sub,
            @JsonProperty(value = VOT_CLAIM_NAME, required = true) Vot vot,
            @JsonProperty(value = "vtm", required = true) String vtm,
            @JsonProperty(value = "credentials", required = true) List<String> credentialSignatures,
            @JsonProperty(value = VCS_CLAIM_NAME, required = true) List<String> vcs,
            @JsonProperty(value = IDENTITY_CLAIM_NAME) IdentityClaim identityClaim,
            @JsonProperty(value = ADDRESS_CLAIM_NAME) List<PostalAddress> addressClaim,
            @JsonProperty(value = PASSPORT_CLAIM_NAME) List<PassportDetails> passportClaim,
            @JsonProperty(value = DRIVING_PERMIT_CLAIM_NAME)
                    List<DrivingPermitDetails> drivingPermitClaim,
            @JsonProperty(value = NINO_CLAIM_NAME) List<SocialSecurityRecordDetails> ninoClaim) {
        super(identityClaim, addressClaim, passportClaim, drivingPermitClaim, ninoClaim);
        this.sub = sub;
        this.vot = vot;
        this.vtm = vtm;
        this.credentialSignatures = credentialSignatures;
        this.vcs = vcs;
    }
}
