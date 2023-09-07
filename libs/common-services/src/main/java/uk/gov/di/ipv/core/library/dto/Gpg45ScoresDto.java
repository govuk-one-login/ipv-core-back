package uk.gov.di.ipv.core.library.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Gpg45ScoresDto {
    public static Gpg45ScoresDto fromGpg45Scores(Gpg45Scores scores) {
        return new Gpg45ScoresDto(
                scores.getEvidences().stream().map(EvidenceDto::fromEvidence).toList(),
                scores.getActivity(),
                scores.getFraud(),
                scores.getVerification());
    }

    private List<EvidenceDto> evidences;
    private int activity;
    private int fraud;
    private int verification;
}
