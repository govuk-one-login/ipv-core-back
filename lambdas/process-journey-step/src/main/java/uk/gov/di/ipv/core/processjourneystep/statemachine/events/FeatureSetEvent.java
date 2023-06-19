package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.processjourneystep.statemachine.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyStepResponse;

import java.util.Map;

@Data
public class FeatureSetEvent implements Event {
    private static final Logger LOGGER = LogManager.getLogger();

    private String name;
    private Map<String, BasicEvent> featureSets;
    private State targetState;
    private JourneyStepResponse response;

    @Override
    public StateMachineResult resolve(JourneyContext journeyContext) {
        String featureSet = journeyContext.getFeatureSet();
        BasicEvent featureSetEventAction = featureSets.get(featureSet);
        if (featureSetEventAction != null) {
            LOGGER.info("featureSetEventAction found: {}", featureSetEventAction.getName());
            return featureSetEventAction.resolve(journeyContext);
        }
        LOGGER.info("featureSetEventAction not found for {}, using default", featureSet);
        return featureSets.get("default").resolve(journeyContext);
    }
}
