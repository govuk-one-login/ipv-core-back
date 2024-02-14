package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionsIpvJourneyStart implements AuditExtensions {

    public static final String REPROVE_IDENTITY_KEY = "reprove_identity";

    @JsonProperty("vtr")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private final List<String> vtr;

    @JsonProperty("reprove_identity")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private final Boolean reproveIdentity;

    public AuditExtensionsIpvJourneyStart(
            @JsonProperty(value = "reprove_identity", required = false) Boolean reproveIdentity,
            @JsonProperty(value = "vtr", required = false) List<String> vtr) {
        this.reproveIdentity = reproveIdentity;
        this.vtr = vtr;
    }
}
