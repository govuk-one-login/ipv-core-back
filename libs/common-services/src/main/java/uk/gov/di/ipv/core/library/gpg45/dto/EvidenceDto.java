package uk.gov.di.ipv.core.library.gpg45.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
@NoArgsConstructor
@AllArgsConstructor
public class EvidenceDto {
    public static EvidenceDto fromEvidence(Gpg45Scores.Evidence evidence) {
        return new EvidenceDto(evidence.getStrength(), evidence.getValidity());
    }

    private int strength;
    private int validity;
}
