package uk.gov.di.ipv.core.library.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class MitigationJourneyDetailsDto {
    private String mitigationJourneyId;
    private boolean complete;
}
