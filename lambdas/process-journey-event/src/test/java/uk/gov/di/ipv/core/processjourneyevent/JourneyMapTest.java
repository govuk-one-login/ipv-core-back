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
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(SystemStubsExtension.class)
public class JourneyMapTest {
    @SystemStub private static EnvironmentVariables environmentVariables;

    @BeforeAll
    public static void beforeAll() {
        environmentVariables.set("IS_LOCAL", "true");
    }

    @ParameterizedTest
    @EnumSource
    void shouldHandleSameEventsForAllCris(IpvJourneyTypes journeyType) throws IOException {
        var stateMachineInitializer = new StateMachineInitializer(journeyType);
        var stateMachine = stateMachineInitializer.initialize();

        var criStatesAndEvents = new ArrayList<StateAndEvents>();
        var allCriEvents = new HashSet<String>();
        findCriStatesAndEvents(stateMachine, criStatesAndEvents, allCriEvents);

        for (var stateAndEvents : criStatesAndEvents) {
            var missingCriEvents = new HashSet<>(allCriEvents);
            missingCriEvents.removeAll(stateAndEvents.events());

            assertEquals(
                    allCriEvents,
                    stateAndEvents.events(),
                    String.format(
                            "%s doesn't handle these CRI state events: %s",
                            stateAndEvents.state(), missingCriEvents));
        }
    }

    @ParameterizedTest
    @EnumSource
    void shouldHandleSameEventsForSamePage(IpvJourneyTypes journeyType) throws IOException {
        var stateMachineInitializer = new StateMachineInitializer(journeyType);
        var stateMachine = stateMachineInitializer.initialize();

        var pageMap = new HashMap<String, List<StateAndEvents>>();
        findPageSpecificStatesAndEvents(stateMachine, pageMap);

        for (var statesAndEvents : pageMap.values()) {
            var pageEvents = new HashSet<String>();

            for (var stateAndEvents : statesAndEvents) {
                pageEvents.addAll(stateAndEvents.events());
            }

            for (var stateAndEvents : statesAndEvents) {
                var missingPageEvents = new HashSet<>(pageEvents);
                missingPageEvents.removeAll(stateAndEvents.events());

                assertEquals(
                        pageEvents,
                        stateAndEvents.events(),
                        String.format(
                                "%s doesn't handle these events for this page: %s",
                                stateAndEvents.state(), missingPageEvents));
            }
        }
    }

    @ParameterizedTest
    @EnumSource
    void shouldMatchNestedJourneyEntryEvents(IpvJourneyTypes journeyType) throws IOException {
        var stateMachineInitialiser = new StateMachineInitializer(journeyType);

        var stateMachine = stateMachineInitialiser.initialize();
        var stateMachineKeys = stateMachine.keySet();

        for (var targetKey : stateMachineKeys) {
            var targetState = stateMachine.get(targetKey);

            if (targetState instanceof NestedJourneyInvokeState targetNestedState) {
                var expectedEntryEvents =
                        targetNestedState.getNestedJourneyDefinition().getEntryEvents().keySet();

                for (var sourceKey : stateMachineKeys) {
                    var sourceState = stateMachine.get(sourceKey);

                    if (sourceState instanceof BasicState sourceBasicState) {
                        var sourceEvents = sourceBasicState.getEvents();

                        for (var entry : sourceEvents.entrySet()) {
                            String sourceEventName = entry.getKey();
                            Event sourceEvent = entry.getValue();

                            if (sourceEvent instanceof BasicEvent sourceBasicEvent) {
                                if (Objects.equals(sourceBasicEvent.getTargetState(), targetKey)) {
                                    assertTrue(
                                            expectedEntryEvents.contains(sourceEventName),
                                            String.format(
                                                    "%s has unexpected entry event: %s, from %s",
                                                    targetKey, sourceEventName, sourceKey));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    @ParameterizedTest
    @EnumSource
    void shouldMatchNestedJourneyExitEvents(IpvJourneyTypes journeyType) throws IOException {
        var stateMachineInitialiser = new StateMachineInitializer(journeyType);

        var stateMachine = stateMachineInitialiser.initialize();
        var stateMachineKeys = stateMachine.keySet();

        for (var key : stateMachineKeys) {
            var state = stateMachine.get(key);

            if (state instanceof NestedJourneyInvokeState) {
                var exitEvents = ((NestedJourneyInvokeState) state).getExitEvents().keySet();
                var actualExitEvents = getActualExitEvents((NestedJourneyInvokeState) state);

                assertEquals(
                        exitEvents,
                        actualExitEvents,
                        String.format(
                                "%s doesn't have matching exit states to nested journey", state));
            }
        }
    }

    private static HashSet<String> getActualExitEvents(NestedJourneyInvokeState state) {
        var actualExitEvents = new HashSet<String>();

        var nestedStateMap = state.getNestedJourneyDefinition().getNestedJourneyStates();
        for (var nestedState : nestedStateMap.values()) {
            if (nestedState instanceof BasicState basicState) {
                var events = basicState.getEvents().values();
                for (var event : events) {
                    if (event instanceof ExitNestedJourneyEvent exitNestedJourneyEvent) {
                        actualExitEvents.add(exitNestedJourneyEvent.getExitEventToEmit());
                    }
                }
            }
        }
        return actualExitEvents;
    }

    private void findCriStatesAndEvents(
            Map<String, State> stateMachine,
            List<StateAndEvents> criStatesAndEvents,
            Set<String> allCriEvents) {
        for (var entry : stateMachine.entrySet()) {
            var key = entry.getKey();
            var state = entry.getValue();

            if (state instanceof BasicState basicState) {
                var response = basicState.getResponse();

                if (response instanceof CriStepResponse) {
                    var criEvents = new HashSet<>(basicState.getEvents().keySet());
                    var parentEvents = basicState.getParentObj().getEvents().keySet();
                    criEvents.addAll(parentEvents);

                    criStatesAndEvents.add(new StateAndEvents(key, criEvents));
                    allCriEvents.addAll(criEvents);
                }
            } else if (state instanceof NestedJourneyInvokeState nestedState) {
                var nestedStateMachine =
                        nestedState.getNestedJourneyDefinition().getNestedJourneyStates();
                findCriStatesAndEvents(nestedStateMachine, criStatesAndEvents, allCriEvents);
            }
        }
    }

    private void findPageSpecificStatesAndEvents(
            Map<String, State> stateMachine, Map<String, List<StateAndEvents>> pageMap) {
        for (var key : stateMachine.keySet()) {
            var state = stateMachine.get(key);

            if (state instanceof BasicState basicState) {
                var response = basicState.getResponse();

                if (response instanceof PageStepResponse pageStepResponse) {
                    var pageId = (String) pageStepResponse.value().get("page");
                    var pageEvents = basicState.getEvents().keySet();

                    pageMap.computeIfAbsent(pageId, k -> new ArrayList<>())
                            .add(new StateAndEvents(key, pageEvents));
                }
            } else if (state instanceof NestedJourneyInvokeState nestedState) {
                var nestedStateMachine =
                        nestedState.getNestedJourneyDefinition().getNestedJourneyStates();
                findPageSpecificStatesAndEvents(nestedStateMachine, pageMap);
            }
        }
    }

    public record StateAndEvents(String state, Set<String> events) {}
}
