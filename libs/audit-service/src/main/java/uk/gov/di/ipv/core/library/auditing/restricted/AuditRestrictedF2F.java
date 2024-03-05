package uk.gov.di.ipv.core.library.auditing.restricted;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.shaded.json.JSONArray;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditRestrictedF2F implements AuditRestricted {
    @JsonProperty("name")
    private final JSONArray name;

    @JsonProperty("docExpiryDate")
    private String docExpiryDate;

    public AuditRestrictedF2F(
            @JsonProperty(value = "name", required = true) JSONArray name,
            @JsonProperty(value = "docExpiryDate", required = true) String docExpiryDate) {
        this.name = name;
        this.docExpiryDate = docExpiryDate;
    }

    public AuditRestrictedF2F(@JsonProperty(value = "name", required = true) JSONArray name) {
        this.name = name;
    }
}
