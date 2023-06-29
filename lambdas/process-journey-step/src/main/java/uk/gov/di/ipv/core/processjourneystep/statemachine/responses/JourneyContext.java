package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import lombok.Data;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Data
@ExcludeFromGeneratedCoverageReport
public class JourneyContext {
    private String featureSet;

    private JourneyContext() {}

    public static JourneyContext emptyContext() {
        return new JourneyContext();
    }

    public static JourneyContext withFeatureSet(String featureSet) {
        JourneyContext journeyContext = new JourneyContext();
        journeyContext.setFeatureSet(featureSet);
        return journeyContext;
    }
}
