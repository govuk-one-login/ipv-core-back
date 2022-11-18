package uk.gov.di.ipv.core.library.dto;

import lombok.Getter;
import lombok.Setter;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ContractIndicator;

import java.util.Collections;
import java.util.List;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Getter
@Setter
public class ContraIndicatorMitigationDetailsDto {
    private ContractIndicator ci;
    private List<MitigationJourneyDetailsDto> mitigationJourneys;
    private boolean mitigatable;

    public ContraIndicatorMitigationDetailsDto() {}

    public ContraIndicatorMitigationDetailsDto(
            ContractIndicator ci,
            List<MitigationJourneyDetailsDto> mitigationJourneys,
            boolean mitigatable) {
        this.ci = ci;
        this.mitigationJourneys = mitigationJourneys;
        this.mitigatable = mitigatable;
    }

    public ContraIndicatorMitigationDetailsDto(ContractIndicator ci) {
        this.ci = ci;
        this.mitigationJourneys = Collections.emptyList();
        this.mitigatable = true;
    }
}
