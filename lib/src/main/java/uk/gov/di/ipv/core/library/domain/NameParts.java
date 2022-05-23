package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@JsonPropertyOrder({"value", "type"})
@ExcludeFromGeneratedCoverageReport
public class NameParts {
    private String value;
    private String type;

    public NameParts() {}

    public NameParts(String value, String type) {
        this.value = value;
        this.type = type;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @Override
    public String toString() {
        return "NameParts{" + "value='" + value + '\'' + ", type='" + type + '\'' + '}';
    }
}
