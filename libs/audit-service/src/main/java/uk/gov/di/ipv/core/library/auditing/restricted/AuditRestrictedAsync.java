package uk.gov.di.ipv.core.library.auditing.restricted;

import com.fasterxml.jackson.annotation.JsonCreator;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.model.Name;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditRestrictedAsync implements AuditRestricted {
    private final List<Name> name;

    private String docExpiryDate;

    @JsonCreator
    public AuditRestrictedAsync(List<Name> name, String docExpiryDate) {
        this.name = name;
        this.docExpiryDate = docExpiryDate;
    }

    public AuditRestrictedAsync(List<Name> name) {
        this.name = name;
    }
}
