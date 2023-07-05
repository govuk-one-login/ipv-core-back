package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
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

    @JsonProperty("txn")
    private List<String> txn;

    @JsonProperty("mitigation")
    private List<MitigationDto> mitigation;

    @JsonProperty("incompleteMitigation")
    private List<MitigationDto> incompleteMitigation;
}
