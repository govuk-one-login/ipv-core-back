package uk.gov.di.ipv.core.library.dto;

import lombok.Getter;
import lombok.Setter;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Getter
@Setter
public class MitigationJourneyDetailsDto {
    private String mitigationJourneyId;
    private boolean complete;
}
