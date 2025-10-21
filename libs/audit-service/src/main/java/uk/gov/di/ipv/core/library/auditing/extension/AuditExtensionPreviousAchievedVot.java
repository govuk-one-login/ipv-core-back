package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.Vot;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionPreviousAchievedVot implements AuditExtensions {

    @JsonProperty("previous_achieved_vot")
    private final Vot previousAchievedVot;

    @JsonProperty("previous_achieved_max_vot")
    private final Vot previousAchievedMaxVot;

    @JsonCreator
    public AuditExtensionPreviousAchievedVot(
            @JsonProperty(value = "previous_achieved_vot", required = true) Vot previousAchievedVot,
            @JsonProperty(value = "previous_achieved_max_vot", required = true)
                    Vot previousAchievedMaxVot) {
        this.previousAchievedVot = previousAchievedVot;
        this.previousAchievedMaxVot = previousAchievedMaxVot;
    }
}
