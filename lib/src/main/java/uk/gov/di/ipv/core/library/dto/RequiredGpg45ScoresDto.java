package uk.gov.di.ipv.core.library.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RequiredGpg45ScoresDto {
    private Gpg45Profile profile;
    private Gpg45Scores requiredScores;
}
