package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.List;

public class AuditExtensionsIpv extends AuditExtensionsVcEvidence {

    @JsonProperty("vot")
    private final String vot;

    @JsonProperty("vtr")
    private final List<String> vtr;

    public AuditExtensionsIpv(
            @JsonProperty(value = "iss", required = false) String iss,
            @JsonProperty(value = "evidence", required = false) String evidence,
            @JsonProperty(value = "successful", required = false) boolean successful,
            @JsonProperty(value = "vot", required = false) String vot,
            @JsonProperty(value = "vtr", required = false) List<String> vtr)
            throws JsonProcessingException {
        super(iss, evidence, successful);
        this.vot = vot;
        this.vtr = vtr;
    }
}
