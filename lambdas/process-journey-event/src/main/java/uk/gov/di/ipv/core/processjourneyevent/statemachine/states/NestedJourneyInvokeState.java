package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolveParameters;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.MissingSecurityCheckCredential;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;

import java.text.ParseException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;

import static java.util.Objects.requireNonNullElse;
import static uk.gov.di.ipv.core.library.domain.JourneyState.JOURNEY_STATE_DELIMITER;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class NestedJourneyInvokeState implements State {
    private static final Logger LOGGER = LogManager.getLogger();
    private String nestedJourney;
    private NestedJourneyDefinition nestedJourneyDefinition;
    private Map<String, Event> exitEvents;
    private String name;
    private IpvJourneyTypes journeyType;

    @Override
    public TransitionResult transition(
            String eventName, String startState, EventResolveParameters eventResolveParameters)
            throws UnknownEventException, UnknownStateException, CiExtractionException,
                    CredentialParseException, ConfigException, ParseException,
                    MissingSecurityCheckCredential {
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
            result = event.resolve(eventResolveParameters);
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
                            eventName,
                            String.join(JOURNEY_STATE_DELIMITER, stateNameParts),
                            eventResolveParameters);
        }

        if (result.state() instanceof NestedJourneyInvokeState) {
            var entryEvent = requireNonNullElse(result.targetEntryEvent(), eventName);
            return result.state()
                    .transition(
                            entryEvent,
                            String.join(JOURNEY_STATE_DELIMITER, stateNameParts),
                            eventResolveParameters);
        }

        return result;
    }

    private Queue<String> getStateNameParts(String stateName) {
        return new LinkedList<>(Arrays.asList(stateName.split(JOURNEY_STATE_DELIMITER)));
    }

    @Override
    public String toString() {
        return this.name;
    }
}
