package uk.gov.di.ipv.core.library.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Collections;
import java.util.List;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ContraIndicatorMitigationDetailsDto {
    private String ci;
    private List<MitigationJourneyDetailsDto> mitigationJourneys;
    private boolean mitigatable;

    public ContraIndicatorMitigationDetailsDto(String ci) {
        this.ci = ci;
        this.mitigationJourneys = Collections.emptyList();
        this.mitigatable = true;
    }
}
