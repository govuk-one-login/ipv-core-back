package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.Vot;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionPreviousAchievedVot(
        @JsonProperty(value = "previous_achieved_vot", required = true) Vot previousAchievedVot,
        @JsonProperty(value = "previous_achieved_max_vot", required = true)
                Vot previousAchievedMaxVot)
        implements AuditExtensions {}
