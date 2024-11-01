package uk.gov.di.ipv.core.processmobileappcallback.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class MobileAppCallbackRequest {
    private String ipvSessionId;
    private String state;

    private String ipAddress;
    private String deviceInformation;
    private List<String> featureSet;
}
