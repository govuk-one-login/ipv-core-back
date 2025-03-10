package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.MissingSecurityCheckCredential;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;

import java.text.ParseException;
import java.util.Map;

@SuppressWarnings({"javaarchitecture:S7027"}) // Circular dependency with implementations
@JsonTypeInfo(use = JsonTypeInfo.Id.DEDUCTION)
@JsonSubTypes({
    @JsonSubTypes.Type(value = BasicEvent.class),
    @JsonSubTypes.Type(value = ExitNestedJourneyEvent.class)
})
public interface Event {

    TransitionResult resolve(EventResolveParameters resolveParameters)
            throws UnknownEventException, MissingSecurityCheckCredential, CiExtractionException,
                    CredentialParseException, ParseException, ConfigException;

    void initialize(
            String name, Map<String, State> states, Map<String, Event> nestedJourneyExitEvents);
}
