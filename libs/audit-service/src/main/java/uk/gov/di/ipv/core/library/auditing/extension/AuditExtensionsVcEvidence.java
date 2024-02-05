package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.Vot;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionsVcEvidence implements AuditExtensions {
    @JsonProperty("iss")
    private final String iss;

    @JsonProperty("evidence")
    private final JsonNode evidence;

    @JsonProperty("successful")
    @JsonInclude(NON_NULL)
    private final Boolean successful;

    @JsonProperty("isUkIssued")
    @JsonInclude(NON_NULL)
    private final Boolean isUkIssued;

    @JsonProperty("age")
    @JsonInclude(NON_NULL)
    private final Integer age;

    @JsonProperty("vot")
    @JsonInclude(NON_NULL)
    private final Vot vot;

    public AuditExtensionsVcEvidence(
            @JsonProperty(value = "iss", required = false) String iss,
            @JsonProperty(value = "evidence", required = false) String evidence,
            @JsonProperty(value = "successful", required = false) Boolean successful,
            @JsonProperty(value = "isUkIssued", required = false) Boolean isUkIssued,
            @JsonProperty(value = "age", required = false) Integer age,
            @JsonProperty(value = "vot", required = false) Vot vot)
            throws JsonProcessingException {
        this.iss = iss;
        this.evidence = evidence == null ? null : new ObjectMapper().readTree(evidence);
        this.successful = successful;
        this.isUkIssued = isUkIssued;
        this.age = age;
        this.vot = vot;
    }
}
