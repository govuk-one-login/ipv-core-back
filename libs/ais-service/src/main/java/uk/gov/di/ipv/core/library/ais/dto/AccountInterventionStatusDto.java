package uk.gov.di.ipv.core.library.ais.dto;

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
    private Intervention intervention;
    private AccountState state;
    private AisAuditLevel auditLevel;
    private InterventionHistory[] history;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Intervention {
        private long updatedAt;
        private long appliedAt;
        private long sentAt;
        private AisInterventionType description;
        private Long reprovedIdentityAt;
        private Long resetPasswordAt;
        private Long accountDeletedAt;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AccountState {
        private boolean blocked;
        private boolean suspended;
        private boolean reproveIdentity;
        private boolean resetPassword;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class InterventionHistory {
        private String sentAt;
        private String component;
        private String code;
        private String intervention;
        private String reason;
        private String originatingComponent;
        private String originatorReferenceId;
        private String requesterId;
    }
}
