package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.EqualsAndHashCode;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@EqualsAndHashCode
public class BirthDate {
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private String value;

    public BirthDate() {}

    public BirthDate(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
