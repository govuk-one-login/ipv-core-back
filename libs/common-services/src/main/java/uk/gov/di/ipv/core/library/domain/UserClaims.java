package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
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

@Builder
@Getter
@Setter
@ExcludeFromGeneratedCoverageReport
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserClaims {
    @JsonProperty(IDENTITY_CLAIM_NAME)
    private IdentityClaim identityClaim;

    @JsonProperty(ADDRESS_CLAIM_NAME)
    private List<PostalAddress> addressClaim;

    @JsonProperty(PASSPORT_CLAIM_NAME)
    private List<PassportDetails> passportClaim;

    @JsonProperty(DRIVING_PERMIT_CLAIM_NAME)
    private List<DrivingPermitDetails> drivingPermitClaim;

    @JsonProperty(NINO_CLAIM_NAME)
    private List<SocialSecurityRecordDetails> ninoClaim;

    public UserClaims(
            @JsonProperty(value = IDENTITY_CLAIM_NAME) IdentityClaim identityClaim,
            @JsonProperty(value = ADDRESS_CLAIM_NAME) List<PostalAddress> addressClaim,
            @JsonProperty(value = PASSPORT_CLAIM_NAME) List<PassportDetails> passportClaim,
            @JsonProperty(value = DRIVING_PERMIT_CLAIM_NAME)
                    List<DrivingPermitDetails> drivingPermitClaim,
            @JsonProperty(value = NINO_CLAIM_NAME) List<SocialSecurityRecordDetails> ninoClaim) {
        this.identityClaim = identityClaim;
        this.addressClaim = addressClaim;
        this.passportClaim = passportClaim;
        this.drivingPermitClaim = drivingPermitClaim;
        this.ninoClaim = ninoClaim;
    }
}
