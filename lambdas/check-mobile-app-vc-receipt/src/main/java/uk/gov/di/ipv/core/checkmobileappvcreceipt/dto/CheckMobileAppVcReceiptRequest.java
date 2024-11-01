package uk.gov.di.ipv.core.checkmobileappvcreceipt.dto;

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
public class CheckMobileAppVcReceiptRequest {
    private String ipvSessionId;
    private String ipAddress;
    private String deviceInformation;
    private List<String> featureSet;
}
