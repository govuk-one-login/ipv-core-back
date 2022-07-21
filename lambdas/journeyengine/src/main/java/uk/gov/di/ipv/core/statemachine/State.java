package uk.gov.di.ipv.core.statemachine;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class State {

    private String name;
    private State parent;
    private Map<String, Event> events = new HashMap<>();

    public State(String name){
        this.name = name;
    }

    public State withEvent(BasicEvent basicEvent){
        events.put(basicEvent.getName(), basicEvent);
        return this;
    }

    public State withParent(State parent){
        this.parent = parent;
        return this;
    }

    public StateMachineResult transition(String eventName, Context context) throws UnknownEventException {
        var event = getEvent(eventName);
        if (event.isPresent()){
            return event.get().resolve(context);
        }
        throw new UnknownEventException(eventName);
    }

    private Optional<Event> getEvent(String eventName){
        var event = events.get(eventName);
        if (event == null && parent != null){
            return parent.getEvent(eventName);
        }
        return Optional.ofNullable(event);
    }

    public String getName() {
        return name;
    }
}
