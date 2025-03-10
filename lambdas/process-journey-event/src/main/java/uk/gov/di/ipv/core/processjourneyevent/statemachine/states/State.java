package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolveParameters;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.MissingSecurityCheckCredential;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;

import java.text.ParseException;

@JsonTypeInfo(use = JsonTypeInfo.Id.DEDUCTION)
@JsonSubTypes({
    @JsonSubTypes.Type(value = BasicState.class),
    @JsonSubTypes.Type(value = NestedJourneyInvokeState.class),
})
public interface State {
    TransitionResult transition(
            String eventName, String startState, EventResolveParameters eventResolveParameters)
            throws UnknownEventException, UnknownStateException, CiExtractionException,
                    CredentialParseException, ConfigException, ParseException,
                    MissingSecurityCheckCredential;

    IpvJourneyTypes getJourneyType();
}
