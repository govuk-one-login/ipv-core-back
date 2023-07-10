package uk.gov.di.ipv.core.library.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContraIndicatorDto {
    private String code;
    private String issuanceDate;
    private String document;
    private List<String> txn;
    private List<MitigationDto> mitigation;
    private List<MitigationDto> incompleteMitigation;
}
