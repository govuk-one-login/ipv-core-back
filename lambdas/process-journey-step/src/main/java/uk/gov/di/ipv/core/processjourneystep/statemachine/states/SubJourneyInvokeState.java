package uk.gov.di.ipv.core.processjourneystep.statemachine.states;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SubJourneyInvokeState implements State {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String DELIMITER = "/";
    private String subJourney;
    private SubJourneyDefinition subJourneyDefinition;
    private Map<String, Event> exitEvents;
    private String name;

    public SubJourneyInvokeState(String name) {
        this.name = name;
    }

    public State transition(String eventName, String startState, JourneyContext journeyContext)
            throws UnknownEventException {
        Queue<String> stateNameParts = new LinkedList<>(Arrays.asList(startState.split(DELIMITER)));

        State nextState;
        if (stateNameParts.size() == 1) { // We've not descended into the sub-states yet
            LOGGER.debug("stateNameParts size == 1");
            nextState =
                    subJourneyDefinition.getEntryEvents().get(eventName).resolve(journeyContext);
            LOGGER.debug("nextState == '{}'", nextState.getName());
        } else {
            String removed = stateNameParts.remove();
            LOGGER.debug("removed: '{}'", removed);
            String currentSubStateName = stateNameParts.peek();
            LOGGER.debug("currentSubState: '{}'", currentSubStateName);
            State currentSubState =
                    subJourneyDefinition.getSubJourneyStates().get(currentSubStateName);
            nextState =
                    currentSubState.transition(
                            eventName, String.join("/", stateNameParts), journeyContext);
            LOGGER.debug("nextState == '{}'", nextState.getName());
        }

        if (nextState instanceof SubJourneyInvokeState) {
            LOGGER.debug("nextState is instance of SubJourneyInvokeState");
            // recursive stuff. Icky.
            return nextState.transition(
                    eventName, String.join("/", stateNameParts), journeyContext);
        }

        LOGGER.debug("returning nextState: '{}'", nextState.getName());
        return nextState;
    }

    @Override
    public String toString() {
        return this.name;
    }
}
