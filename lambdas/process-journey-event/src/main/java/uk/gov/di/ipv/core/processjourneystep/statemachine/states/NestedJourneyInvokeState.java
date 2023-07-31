package uk.gov.di.ipv.core.processjourneystep.statemachine.states;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;

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

    public State transition(String eventName, String startState, JourneyContext journeyContext)
            throws UnknownEventException, UnknownStateException {
        Queue<String> stateNameParts = getStateNameParts(startState);

        State nextState;
        if (stateNameParts.size() == 1) { // We've not descended into the nested-states yet
            Event event = nestedJourneyDefinition.getEntryEvents().get(eventName);
            if (event == null) {
                throw new UnknownEventException(
                        String.format(
                                "Unknown entry event '%s' for '%s' state nested journey definition",
                                eventName, name));
            }
            nextState = event.resolve(journeyContext);
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
            nextState =
                    currentNestedState.transition(
                            eventName, String.join(DELIMITER, stateNameParts), journeyContext);
        }

        if (nextState instanceof NestedJourneyInvokeState) {
            return nextState.transition(
                    eventName, String.join(DELIMITER, stateNameParts), journeyContext);
        }

        return nextState;
    }

    private Queue<String> getStateNameParts(String stateName) {
        return new LinkedList<>(Arrays.asList(stateName.split(DELIMITER)));
    }

    @Override
    public String toString() {
        return this.name;
    }
}
