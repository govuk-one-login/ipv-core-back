package uk.gov.di.ipv.core.library.ais.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.ais.enums.AisAuditLevel;
import uk.gov.di.ipv.core.library.ais.enums.AisInterventionType;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccountInterventionStatusDto {
    @JsonProperty private Intervention intervention;
    @JsonProperty private AccountState state;
    @JsonProperty private AisAuditLevel auditLevel;
    @JsonProperty private InterventionHistory[] history;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Intervention {
        @JsonProperty private long updatedAt;
        @JsonProperty private long appliedAt;
        @JsonProperty private long sentAt;
        @JsonProperty private AisInterventionType description;
        @JsonProperty private Long reprovedIdentityAt;
        @JsonProperty private Long resetPasswordAt;
        @JsonProperty private Long accountDeletedAt;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AccountState {
        @JsonProperty private boolean blocked;
        @JsonProperty private boolean suspended;
        @JsonProperty private boolean reproveIdentity;
        @JsonProperty private boolean resetPassword;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class InterventionHistory {
        @JsonProperty private String sentAt;
        @JsonProperty private String component;
        @JsonProperty private String code;
        @JsonProperty private String intervention;
        @JsonProperty private String reason;
        @JsonProperty private String originatingComponent;
        @JsonProperty private String originatorReferenceId;
        @JsonProperty private String requesterId;
    }
}
