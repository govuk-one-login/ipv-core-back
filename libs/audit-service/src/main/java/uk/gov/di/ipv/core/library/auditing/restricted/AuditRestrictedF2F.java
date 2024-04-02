package uk.gov.di.ipv.core.library.auditing.restricted;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Name;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditRestrictedF2F implements AuditRestricted {
    @JsonProperty("name")
    private final List<Name> name;

    @JsonProperty("docExpiryDate")
    private String docExpiryDate;

    public AuditRestrictedF2F(
            @JsonProperty(value = "name", required = true) List<Name> name,
            @JsonProperty(value = "docExpiryDate", required = true) String docExpiryDate) {
        this.name = name;
        this.docExpiryDate = docExpiryDate;
    }

    public AuditRestrictedF2F(@JsonProperty(value = "name", required = true) List<Name> name) {
        this.name = name;
    }
}
