package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Data;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@JsonPropertyOrder({"value", "type"})
@ExcludeFromGeneratedCoverageReport
@Data
public class NameParts {
    private String value;
    private String type;

    public NameParts() {}

    public NameParts(
            @JsonProperty(value = "value", required = true) String value,
            @JsonProperty(value = "type", required = true) String type) {
        this.value = value;
        this.type = type;
    }
}
