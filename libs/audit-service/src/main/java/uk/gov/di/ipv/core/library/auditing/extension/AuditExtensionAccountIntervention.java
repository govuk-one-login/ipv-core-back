package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuditExtensionAccountIntervention implements AuditExtensions {

    private static final String REPROVE_IDENTITY_TYPE = "reprove_identity";

    @JsonProperty private Boolean success;
    @JsonProperty private final String type;

    private AuditExtensionAccountIntervention(String type) {
        this.type = type;
    }

    private AuditExtensionAccountIntervention(String type, Boolean success) {
        this.type = type;
        this.success = success;
    }

    public static AuditExtensionAccountIntervention
            newReproveIdentityAuditExtensionAccountIntervention() {
        return new AuditExtensionAccountIntervention(REPROVE_IDENTITY_TYPE);
    }

    public static AuditExtensionAccountIntervention
            newReproveIdentityAuditExtensionAccountIntervention(boolean success) {
        return new AuditExtensionAccountIntervention(REPROVE_IDENTITY_TYPE, success);
    }
}
