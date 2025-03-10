package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import lombok.Data;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.MissingSecurityCheckCredential;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;

import java.text.ParseException;
import java.util.Map;

@Data
public class ExitNestedJourneyEvent implements Event {

    private String exitEventToEmit;
    private Map<String, Event> nestedJourneyExitEvents;

    @Override
    public TransitionResult resolve(EventResolveParameters resolveParameters)
            throws UnknownEventException, MissingSecurityCheckCredential, CiExtractionException,
                    CredentialParseException, ParseException, ConfigException {
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
