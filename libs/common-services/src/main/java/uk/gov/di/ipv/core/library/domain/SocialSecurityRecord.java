package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Data
public class SocialSecurityRecord {
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    private String personalNumber;

    public SocialSecurityRecord() {}

    public SocialSecurityRecord(String personalNumber) {
        this.personalNumber = personalNumber;
    }
}
