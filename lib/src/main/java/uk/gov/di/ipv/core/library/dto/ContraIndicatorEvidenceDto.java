package uk.gov.di.ipv.core.library.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ContraIndicatorEvidenceDto {
    private String type;
    private List<ContraIndicatorDto> contraIndicator;
}
