package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolveParameters;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolver;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;

@JsonTypeInfo(use = JsonTypeInfo.Id.DEDUCTION)
@JsonSubTypes({
    @JsonSubTypes.Type(value = BasicState.class),
    @JsonSubTypes.Type(value = NestedJourneyInvokeState.class),
})
public interface State {
    TransitionResult transition(
            String eventName,
            String startState,
            EventResolveParameters eventResolveParameters,
            EventResolver eventResolver)
            throws UnknownEventException, UnknownStateException, JourneyEngineException;

    IpvJourneyTypes getJourneyType();
}
