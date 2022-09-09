package uk.gov.di.ipv.core.library.dto;

import lombok.Data;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
public class VcStatusDto {
    private String criIss;
    private Boolean isSuccessfulVc;

    public VcStatusDto() {}

    public VcStatusDto(String criIss, boolean isSuccessfulVc) {
        this.criIss = criIss;
        this.isSuccessfulVc = isSuccessfulVc;
    }
}
