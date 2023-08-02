package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.Data;

@Data
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
