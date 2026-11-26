package uk.gov.di.ipv.core.library.persistence.item;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;

@Builder
@DynamoDbBean
@Data
@AllArgsConstructor
@NoArgsConstructor
public class DynamicRoutingState {
    @Builder.Default private int dummyStepCount = 0;

    // Triage answers. A null value means the question has not been answered.
    private Boolean livesInUk;
}
