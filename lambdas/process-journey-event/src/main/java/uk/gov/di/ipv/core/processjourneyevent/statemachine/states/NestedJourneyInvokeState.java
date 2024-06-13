package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class NestedJourneyInvokeState implements State {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String DELIMITER = "/";
    private String nestedJourney;
    private NestedJourneyDefinition nestedJourneyDefinition;
    private Map<String, Event> exitEvents;
    private String name;
    private IpvJourneyTypes journeyType;

    @Override
    public TransitionResult transition(
            String eventName, String startState, JourneyContext journeyContext)
            throws UnknownEventException, UnknownStateException {
        Queue<String> stateNameParts = getStateNameParts(startState);

        TransitionResult result;
        if (stateNameParts.size() == 1) { // We've not descended into the nested-states yet
            Event event = nestedJourneyDefinition.getEntryEvents().get(eventName);
            if (event == null) {
                throw new UnknownEventException(
                        String.format(
                                "Unknown entry event '%s' for '%s' state nested journey definition",
                                eventName, name));
            }
            result = event.resolve(journeyContext);
        } else {
            stateNameParts.remove();
            State currentNestedState =
                    nestedJourneyDefinition.getNestedJourneyStates().get(stateNameParts.peek());
            if (currentNestedState == null) {
                throw new UnknownStateException(
                        String.format(
                                "State '%s' not found in nested journey definition for `%s`",
                                stateNameParts.peek(), name));
            }
            result =
                    currentNestedState.transition(
                            eventName, String.join(DELIMITER, stateNameParts), journeyContext);
        }

        if (result.state() instanceof NestedJourneyInvokeState) {
            return result.state()
                    .transition(eventName, String.join(DELIMITER, stateNameParts), journeyContext);
        }

        return result;
    }

    private Queue<String> getStateNameParts(String stateName) {
        return new LinkedList<>(Arrays.asList(stateName.split(DELIMITER)));
    }

    @Override
    public String toString() {
        return this.name;
    }
}
