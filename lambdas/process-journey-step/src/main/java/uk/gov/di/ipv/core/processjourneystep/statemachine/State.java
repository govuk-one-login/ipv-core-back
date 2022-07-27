package uk.gov.di.ipv.core.processjourneystep.statemachine;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@ExcludeFromGeneratedCoverageReport
public class State {
    private String name;
    private State parent;
    private Map<String, Event> events = new HashMap<>();

    public State() {}

    public State(String name) {
        this.name = name;
    }

    public StateMachineResult transition(String eventName, JourneyContext journeyContext)
            throws UnknownEventException {
        var event = getEvent(eventName);
        if (event.isPresent()) {
            return event.get().resolve(journeyContext);
        }
        throw new UnknownEventException(eventName);
    }

    private Optional<Event> getEvent(String eventName) {
        var event = events.get(eventName);
        if (event == null && parent != null) {
            return parent.getEvent(eventName);
        }
        return Optional.ofNullable(event);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public State getParent() {
        return parent;
    }

    public void setParent(State parent) {
        this.parent = parent;
    }

    public Map<String, Event> getEvents() {
        return events;
    }

    public void setEvents(Map<String, Event> events) {
        this.events = events;
    }
}
