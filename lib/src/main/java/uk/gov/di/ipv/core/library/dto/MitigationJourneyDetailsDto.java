package uk.gov.di.ipv.core.library.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.MitigationJourneyId;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Getter
@Setter
@AllArgsConstructor
public class MitigationJourneyDetailsDto {
    private MitigationJourneyId mitigationJourneyId;
    private boolean complete;
}
