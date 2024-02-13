package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.AuditExtensionException;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionsVcEvidence implements AuditExtensions {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @JsonProperty("iss")
    private final String iss;

    @JsonProperty("evidence")
    private final JsonNode evidence;

    @JsonProperty("successful")
    @JsonInclude(NON_NULL)
    private final Boolean successful;

    @JsonProperty("vot")
    @JsonInclude(NON_NULL)
    private final Vot vot;

    @JsonProperty("isUkIssued")
    @JsonInclude(NON_NULL)
    private final Boolean isUkIssued;

    @JsonProperty("age")
    @JsonInclude(NON_NULL)
    private final Integer age;

    public AuditExtensionsVcEvidence(
            @JsonProperty(value = "iss", required = false) String iss,
            @JsonProperty(value = "evidence", required = false) String evidence,
            @JsonProperty(value = "successful", required = false) Boolean successful,
            @JsonProperty(value = "vot", required = false) Vot vot,
            @JsonProperty(value = "isUkIssued", required = false) Boolean isUkIssued,
            @JsonProperty(value = "age", required = false) Integer age)
            throws AuditExtensionException {
        try {
            this.iss = iss;
            this.evidence = evidence == null ? null : OBJECT_MAPPER.readTree(evidence);
            this.successful = successful;
            this.vot = vot;
            this.isUkIssued = isUkIssued;
            this.age = age;
        } catch (JsonProcessingException e) {
            throw new AuditExtensionException(e.getMessage()) {};
        }
    }

    public AuditExtensionsVcEvidence(String iss, String evidence, Boolean successful)
            throws AuditExtensionException {
        this(iss, evidence, successful, null, null, null);
    }

    public AuditExtensionsVcEvidence(String iss, String evidence, Boolean successful, Vot vot)
            throws AuditExtensionException {
        this(iss, evidence, successful, vot, null, null);
    }
}
