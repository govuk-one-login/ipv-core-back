package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.ipv.core.library.enums.Vot;

import java.util.List;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

public class AuditExtensionsIpv implements AuditExtensions {

    @JsonProperty("iss")
    private final String iss;

    @JsonProperty("evidence")
    private final JsonNode evidence;

    @JsonProperty("vot")
    @JsonInclude(NON_NULL)
    private final Vot vot;

    @JsonProperty("vtr")
    @JsonInclude(NON_NULL)
    private final List<String> vtr;

    public AuditExtensionsIpv(
            @JsonProperty(value = "iss", required = false) String iss,
            @JsonProperty(value = "evidence", required = false) String evidence,
            @JsonProperty(value = "vot", required = false) Vot vot,
            @JsonProperty(value = "vtr", required = false) List<String> vtr)
            throws JsonProcessingException {
        this.iss = iss;
        this.evidence = evidence == null ? null : new ObjectMapper().readTree(evidence);
        this.vot = vot;
        this.vtr = vtr;
    }
}
