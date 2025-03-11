package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import lombok.Data;
import uk.gov.di.ipv.core.processjourneyevent.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;

import java.util.Map;

@Data
public class ExitNestedJourneyEvent implements Event {

    private String exitEventToEmit;
    private Map<String, Event> nestedJourneyExitEvents;

    @Override
    public TransitionResult resolve(EventResolveParameters resolveParameters)
            throws UnknownEventException, JourneyEngineException {
        Event event = nestedJourneyExitEvents.get(exitEventToEmit);
        if (event == null) {
            throw new UnknownEventException(
                    "Event '%s' not found in nested journey's exit events"
                            .formatted(exitEventToEmit));
        }
        return event.resolve(resolveParameters);
    }

    @Override
    public void initialize(
            String name, Map<String, State> states, Map<String, Event> nestedJourneyExitEvents) {
        throw new UnsupportedOperationException(
                "Initialize of ExitNestedJourneyEvent not supported");
    }
}
