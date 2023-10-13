package uk.gov.di.ipv.core.processjourneyevent;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.StateMachineInitializer;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.BasicEvent;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.ExitNestedJourneyEvent;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyInvokeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.CriStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.PageStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.StepResponse;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(SystemStubsExtension.class)
public class JourneyMapTest {
    @SystemStub private static EnvironmentVariables environmentVariables;

    @BeforeAll
    private static void beforeAll() {
        environmentVariables.set("IS_LOCAL", "true");
    }

    @ParameterizedTest
    @EnumSource
    void shouldHandleSameEventsForAllCris(IpvJourneyTypes journeyType) throws IOException {
        StateMachineInitializer stateMachineInitialiser = new StateMachineInitializer(journeyType);
        Map<String, State> stateMachine = stateMachineInitialiser.initialize();

        List<StateAndEvents> criStates = new ArrayList<>();
        Set<String> criStateEvents = new HashSet<>();
        findCriStatesAndEvents(stateMachine, criStates, criStateEvents);

        for (StateAndEvents stateAndEvents : criStates) {
            assertEquals(
                    criStateEvents,
                    stateAndEvents.events,
                    String.format("%s doesn't handle all CRI state events", stateAndEvents.state));
        }
    }

    @ParameterizedTest
    @EnumSource
    void shouldHandleSameEventsForSamePage(IpvJourneyTypes journeyType) throws IOException {
        StateMachineInitializer stateMachineInitialiser = new StateMachineInitializer(journeyType);
        Map<String, State> stateMachine = stateMachineInitialiser.initialize();

        Map<String, List<StateAndEvents>> pageStateMap = new HashMap<>();
        findPageSpecificStatesAndEvents(stateMachine, pageStateMap);

        for (List<StateAndEvents> statesAndEvents : pageStateMap.values()) {
            Set<String> pageStateEvents = new HashSet<>();

            for (StateAndEvents singleStateAndEvent : statesAndEvents) {
                pageStateEvents.addAll(singleStateAndEvent.events);
            }

            for (StateAndEvents singleStateAndEvent : statesAndEvents) {
                assertEquals(
                        pageStateEvents,
                        singleStateAndEvent.events,
                        String.format(
                                "%s doesn't handle all events for this page",
                                singleStateAndEvent.state));
            }
        }
    }

    @ParameterizedTest
    @EnumSource
    void shouldMatchNestedJourneyEntryEvents(IpvJourneyTypes journeyType) throws IOException {
        StateMachineInitializer stateMachineInitialiser = new StateMachineInitializer(journeyType);

        Map<String, State> stateMachine = stateMachineInitialiser.initialize();
        Set<String> stateMachineKeys = stateMachine.keySet();

        for (String key : stateMachineKeys) {
            State state = stateMachine.get(key);

            if (state instanceof NestedJourneyInvokeState) {
                Set<String> entryEvents =
                        ((NestedJourneyInvokeState) state).getExitEvents().keySet();

                for (String comparingStateKey : stateMachineKeys) {
                    State comparingState = stateMachine.get(comparingStateKey);

                    if (comparingState instanceof BasicState) {
                        Map<String, Event> eventMap = ((BasicState) comparingState).getEvents();

                        for (Map.Entry<String, Event> entry : eventMap.entrySet()) {
                            String eventName = entry.getKey();
                            Event event = entry.getValue();

                            if (event instanceof BasicEvent) {
                                if (((BasicEvent) event).getTargetState() == key) {
                                    assertTrue(entryEvents.contains(eventName));
                                }
                            }
                        }
                    }
                }
            }
            ;
        }
        ;
    }

    @ParameterizedTest
    @EnumSource
    void shouldMatchNestedJourneyExitEvents(IpvJourneyTypes journeyType) throws IOException {
        StateMachineInitializer stateMachineInitialiser = new StateMachineInitializer(journeyType);

        Map<String, State> stateMachine = stateMachineInitialiser.initialize();
        Set<String> stateMachineKeys = stateMachine.keySet();

        for (String key : stateMachineKeys) {
            State state = stateMachine.get(key);

            if (state instanceof NestedJourneyInvokeState) {
                Set<String> exitEvents =
                        ((NestedJourneyInvokeState) state).getExitEvents().keySet();
                Set<String> actualExitEvents = new HashSet<>();

                Map<String, State> nestedStateMap =
                        ((NestedJourneyInvokeState) state)
                                .getNestedJourneyDefinition()
                                .getNestedJourneyStates();
                for (State nestedState : nestedStateMap.values()) {
                    if (nestedState instanceof BasicState) {
                        Collection<Event> events = ((BasicState) nestedState).getEvents().values();
                        for (Event event : events) {
                            if (event instanceof ExitNestedJourneyEvent) {
                                actualExitEvents.add(
                                        ((ExitNestedJourneyEvent) event).getExitEventToEmit());
                            }
                        }
                    }
                }

                assertEquals(
                        exitEvents,
                        actualExitEvents,
                        String.format(
                                "%s doesn't have matching exit states to nested journey", state));
            }
            ;
        }
        ;
    }

    private void findCriStatesAndEvents(
            Map<String, State> stateMachine,
            List<StateAndEvents> criStates,
            Set<String> criEvents) {
        for (Map.Entry<String, State> entry : stateMachine.entrySet()) {
            String key = entry.getKey();
            State state = entry.getValue();

            if (state instanceof BasicState) {
                StepResponse response = ((BasicState) state).getResponse();

                if (response instanceof CriStepResponse) {
                    Set<String> events = ((BasicState) state).getEvents().keySet();

                    criStates.add(new StateAndEvents(key, events));
                    criEvents.addAll(events);
                }
            } else if (state instanceof NestedJourneyInvokeState) {
                Map<String, State> nestedStateMachine =
                        ((NestedJourneyInvokeState) state)
                                .getNestedJourneyDefinition()
                                .getNestedJourneyStates();
                findCriStatesAndEvents(nestedStateMachine, criStates, criEvents);
            }
        }
    }

    private void findPageSpecificStatesAndEvents(
            Map<String, State> stateMachine, Map<String, List<StateAndEvents>> pageStateMap) {
        for (String key : stateMachine.keySet()) {
            State state = stateMachine.get(key);

            if (state instanceof BasicState) {
                StepResponse response = ((BasicState) state).getResponse();

                if (response instanceof PageStepResponse) {
                    String pageId = (String) response.value().get("page");
                    Set<String> events = ((BasicState) state).getEvents().keySet();

                    pageStateMap
                            .computeIfAbsent(pageId, k -> new ArrayList<>())
                            .add(new StateAndEvents(key, events));
                }
            } else if (state instanceof NestedJourneyInvokeState) {
                Map<String, State> nestedStateMachine =
                        ((NestedJourneyInvokeState) state)
                                .getNestedJourneyDefinition()
                                .getNestedJourneyStates();
                findPageSpecificStatesAndEvents(nestedStateMachine, pageStateMap);
            }
        }
    }
}

class StateAndEvents {
    public String state;
    public Set<String> events;

    public StateAndEvents(String state, Set<String> events) {
        this.state = state;
        this.events = events;
    }
}
