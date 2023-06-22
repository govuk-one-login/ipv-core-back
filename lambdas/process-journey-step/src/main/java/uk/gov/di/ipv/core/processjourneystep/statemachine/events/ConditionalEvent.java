package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.processjourneystep.statemachine.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.requiredNotMet.ConditionalRequiredNotMet;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.requires.ConditionalPredicate;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyStepResponse;

import java.util.List;

@Data
public class ConditionalEvent implements Event {
    private static final Logger LOGGER = LogManager.getLogger();
    private String name;
    private State targetState;
    private JourneyStepResponse response;
    private List<ConditionalPredicate> requires;
    private ConditionalRequiredNotMet requiredNotMet;

    @Override
    public StateMachineResult resolve(JourneyContext journeyContext) {
        if (requires.stream().allMatch(ConditionalPredicate::check)) {
            return new StateMachineResult(targetState, response);
        };
        LOGGER.info("Failed to meet conditional step '{}'. Using fallback.", name);
        return requiredNotMet.resolve(journeyContext);
    }
}
