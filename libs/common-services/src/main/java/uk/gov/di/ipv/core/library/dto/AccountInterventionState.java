package uk.gov.di.ipv.core.library.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@DynamoDbBean
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AccountInterventionState {
    private boolean isBlocked;
    private boolean isSuspended;
    private boolean isReproveIdentity;
    private boolean isResetPassword;
}
