package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.Data;

import java.util.List;

@Data
public class JourneyContext {
    private List<String> featureSet;

    private JourneyContext() {}

    public static JourneyContext emptyContext() {
        return new JourneyContext();
    }

    public static JourneyContext withFeatureSet(List<String> featureSet) {
        JourneyContext journeyContext = new JourneyContext();
        journeyContext.setFeatureSet(featureSet);
        return journeyContext;
    }
}
