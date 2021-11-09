package uk.gov.di.ipv.domain.gpg45;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class IdentityProfile {

    @JsonProperty("name")
    private IdentityProfileIdentifier identityProfileIdentifier;

    @JsonProperty("description")
    private String description;

    @JsonProperty("confidence")
    private ConfidenceLevel levelOfConfidence;

    @JsonProperty("evidenceScores")
    private List<EvidenceScore> evidenceScoreCriteria;

    @JsonProperty("activityHistory")
    private Score activityHistory = Score.NOT_AVAILABLE;

    @JsonProperty("identityFraud")
    private Score identityFraud = Score.NOT_AVAILABLE;

    @JsonProperty("verification")
    private Score verification = Score.NOT_AVAILABLE;
}
