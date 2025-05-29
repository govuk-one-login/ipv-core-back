package uk.gov.di.ipv.core.processjourneyevent;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.StateMachineInitializer;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.BasicEvent;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.ExitNestedJourneyEvent;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.JourneyChangeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyInvokeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.CriStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.PageStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.ProcessStepResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static java.util.Objects.requireNonNullElse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JourneyMapTest {

    @Test
    void shouldHandleSameEventsForAllCris() throws IOException {
        var criStatesAndEvents = new ArrayList<StateAndEvents>();
        var allCriEvents = new HashSet<String>();

        for (var journeyType : IpvJourneyTypes.values()) {
            var stateMachineInitializer = new StateMachineInitializer(journeyType);
            var stateMachine = stateMachineInitializer.initialize();

            findCriStatesAndEvents(stateMachine, criStatesAndEvents, allCriEvents);
        }

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

    @Test
    void shouldHandleSameEventsForSameProcessStates() throws IOException {
        var processStateMap = new HashMap<String, List<StateAndEvents>>();

        for (var journeyType : IpvJourneyTypes.values()) {
            var stateMachineInitializer = new StateMachineInitializer(journeyType);
            var stateMachine = stateMachineInitializer.initialize();

            findProcessStatesAndEvents(stateMachine, processStateMap);
        }

        for (var lambdaAndParameters : processStateMap.keySet()) {
            var statesAndEvents = processStateMap.get(lambdaAndParameters);
            var processStateEvents = new HashSet<String>();

            for (var stateAndEvents : statesAndEvents) {
                processStateEvents.addAll(stateAndEvents.events());
            }

            for (var stateAndEvents : statesAndEvents) {
                var missingProcessStateEvents = new HashSet<>(processStateEvents);
                missingProcessStateEvents.removeAll(stateAndEvents.events());

                assertEquals(
                        processStateEvents,
                        stateAndEvents.events(),
                        String.format(
                                "%s using %s doesn't handle these events for this process state: %s",
                                stateAndEvents.state(),
                                lambdaAndParameters,
                                missingProcessStateEvents));
            }
        }
    }

    @Test
    void shouldHandleSameEventsForSamePage() throws IOException {
        var pageMap = new HashMap<String, List<StateAndEvents>>();

        for (var journeyType : IpvJourneyTypes.values()) {
            var stateMachineInitializer = new StateMachineInitializer(journeyType);
            var stateMachine = stateMachineInitializer.initialize();

            findPageSpecificStatesAndEvents(stateMachine, pageMap);
        }

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

                    for (var entry : getOnwardEventMap(sourceState).entrySet()) {
                        String sourceEventName = entry.getKey();
                        Event sourceEvent = entry.getValue();

                        if (sourceEvent instanceof BasicEvent sourceBasicEvent
                                && Objects.equals(sourceBasicEvent.getTargetState(), targetKey)) {
                            var eventToCompare =
                                    requireNonNullElse(
                                            sourceBasicEvent.getTargetEntryEvent(),
                                            sourceEventName);

                            assertTrue(
                                    expectedEntryEvents.contains(eventToCompare),
                                    String.format(
                                            "%s has unexpected entry event: %s, from %s",
                                            targetKey, eventToCompare, sourceKey));
                        }
                    }
                }
            }
        }
    }

    // Get events that might follow from the given state
    private Map<String, Event> getOnwardEventMap(State state) {
        if (state instanceof BasicState basicState) {
            return basicState.getEvents();
        }
        if (state instanceof NestedJourneyInvokeState nestedJourneyInvokeState) {
            return nestedJourneyInvokeState.getExitEvents();
        }
        return Map.of();
    }

    @Test
    void shouldMatchJourneyMapEntryPoints() throws IOException {
        var allBasicStates = new ArrayList<BasicState>();
        var journeyEntryPointUsages = new HashMap<String, JourneyChangeState>();

        for (var journeyType : IpvJourneyTypes.values()) {
            var stateMachine = new StateMachineInitializer(journeyType).initialize();
            var stateMachineKeys = stateMachine.keySet();

            for (var targetKey : stateMachineKeys) {
                var targetState = stateMachine.get(targetKey);
                if (targetState instanceof BasicState basicState) {
                    var events = basicState.getEvents();
                    recordJourneyEntryPointUsages(
                            events,
                            journeyEntryPointUsages,
                            String.format(
                                    "journey: %s, state: %s", journeyType, basicState.getName()));
                    allBasicStates.add(basicState);
                }
            }
        }

        for (var usage : journeyEntryPointUsages.entrySet()) {
            assertFalse(
                    allBasicStates.stream()
                            .filter(
                                    basicState ->
                                            isJourneyChangeStateReferencingBasicState(
                                                    usage.getValue(), basicState))
                            .toList()
                            .isEmpty(),
                    String.format(
                            "%s references undefined journey entry point: journeyType: %s and state: %s",
                            usage.getKey(),
                            usage.getValue().getJourneyType(),
                            usage.getValue().getInitialState()));
        }
    }

    private void recordJourneyEntryPointUsages(
            Map<String, Event> events,
            Map<String, JourneyChangeState> journeyEntryPointUsages,
            String stateReference) {
        for (var event : events.values()) {
            if (event instanceof BasicEvent basicEvent) {
                var targetStateObj = basicEvent.getTargetStateObj();
                if (targetStateObj instanceof JourneyChangeState journeyChangeState) {
                    journeyEntryPointUsages.put(
                            String.format("%s, event: %s", stateReference, basicEvent.getName()),
                            journeyChangeState);
                }
            }
        }
    }

    private boolean isJourneyChangeStateReferencingBasicState(
            JourneyChangeState journeyChangeState, BasicState basicState) {
        return Objects.equals(journeyChangeState.getJourneyType(), basicState.getJourneyType())
                && Objects.equals(journeyChangeState.getInitialState(), basicState.getName());
    }

    @ParameterizedTest
    @EnumSource
    void basicEventTargetStatesShouldExist(IpvJourneyTypes journeyType) throws IOException {
        var stateMachine = new StateMachineInitializer(journeyType).initialize();

        recursiveCheckTargetStatesExist(stateMachine, stateMachine.keySet());
    }

    private void recursiveCheckTargetStatesExist(
            Map<String, State> stateMachine, Set<String> stateNamesInScope) throws IOException {
        var stateMachineKeys = stateMachine.keySet();
        for (var stateNameToCheck : stateMachineKeys) {
            var targetState = stateMachine.get(stateNameToCheck);
            if (targetState instanceof BasicState basicState) {
                checkTargetStatesExist(basicState.getEvents(), stateNamesInScope);
            } else if (targetState instanceof NestedJourneyInvokeState nestedState) {
                var nestedStateMachine =
                        nestedState.getNestedJourneyDefinition().getNestedJourneyStates();
                var combinedStateNames = new HashSet<String>();
                combinedStateNames.addAll(stateNamesInScope);
                combinedStateNames.addAll(nestedStateMachine.keySet());
                recursiveCheckTargetStatesExist(nestedStateMachine, combinedStateNames);
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

    private void checkTargetStatesExist(Map<String, Event> events, Set<String> stateMachineKeys)
            throws IOException {
        if (events == null) {
            return;
        }
        for (var event : events.values()) {
            if (event instanceof BasicEvent basicEvent) {
                if (basicEvent.getTargetJourney() != null) {
                    var basicEventStateMachine =
                            new StateMachineInitializer(
                                            IpvJourneyTypes.valueOf(basicEvent.getTargetJourney()))
                                    .initialize();
                    var basicEventStateMachineKeys = basicEventStateMachine.keySet();
                    assertTrue(
                            basicEventStateMachineKeys.contains(basicEvent.getTargetState()),
                            "Unknown target state %s".formatted(basicEvent.getTargetState()));

                } else if (basicEvent.getTargetState() != null) {
                    assertTrue(
                            stateMachineKeys.contains(basicEvent.getTargetState()),
                            "Unknown target state %s".formatted(basicEvent.getTargetState()));
                }

                // Recursively check other event resolutions
                checkTargetStatesExist(basicEvent.getCheckIfDisabled(), stateMachineKeys);
                checkTargetStatesExist(basicEvent.getCheckFeatureFlag(), stateMachineKeys);
                checkTargetStatesExist(basicEvent.getCheckJourneyContext(), stateMachineKeys);
                checkTargetStatesExist(basicEvent.getCheckMitigation(), stateMachineKeys);
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
                    if (event instanceof BasicEvent basicEvent) {
                        if (basicEvent.getCheckIfDisabled() != null) {
                            basicEvent.getCheckIfDisabled().values().stream()
                                    .filter(ExitNestedJourneyEvent.class::isInstance)
                                    .forEach(
                                            disabledEvent ->
                                                    actualExitEvents.add(
                                                            ((ExitNestedJourneyEvent) disabledEvent)
                                                                    .getExitEventToEmit()));
                        }
                        if (basicEvent.getCheckFeatureFlag() != null) {
                            basicEvent.getCheckFeatureFlag().values().stream()
                                    .filter(ExitNestedJourneyEvent.class::isInstance)
                                    .forEach(
                                            checkFlagEvent ->
                                                    actualExitEvents.add(
                                                            ((ExitNestedJourneyEvent)
                                                                            checkFlagEvent)
                                                                    .getExitEventToEmit()));
                        }
                        if (basicEvent.getCheckJourneyContext() != null) {
                            basicEvent.getCheckJourneyContext().values().stream()
                                    .filter(ExitNestedJourneyEvent.class::isInstance)
                                    .forEach(
                                            checkContextEvent ->
                                                    actualExitEvents.add(
                                                            ((ExitNestedJourneyEvent)
                                                                            checkContextEvent)
                                                                    .getExitEventToEmit()));
                        }
                        if (basicEvent.getCheckMitigation() != null) {
                            basicEvent.getCheckMitigation().values().stream()
                                    .filter(ExitNestedJourneyEvent.class::isInstance)
                                    .forEach(
                                            checkMitigationEvent ->
                                                    actualExitEvents.add(
                                                            ((ExitNestedJourneyEvent)
                                                                            checkMitigationEvent)
                                                                    .getExitEventToEmit()));
                        }
                    }
                }
            }
            if (nestedState instanceof NestedJourneyInvokeState nestedNestedState) {
                for (var event : nestedNestedState.getExitEvents().values()) {
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

    private void findProcessStatesAndEvents(
            Map<String, State> stateMachine, Map<String, List<StateAndEvents>> processStateMap) {
        for (var key : stateMachine.keySet()) {
            var state = stateMachine.get(key);

            if (state instanceof BasicState basicState) {
                var response = basicState.getResponse();

                if (response instanceof ProcessStepResponse processStepResponse) {
                    var lambda = processStepResponse.getLambda();

                    var lambdaInputs = processStepResponse.getLambdaInput();
                    if (lambdaInputs != null) {
                        var inputsInOrder =
                                lambdaInputs.keySet().stream()
                                        .sorted()
                                        .map(k -> String.format("%s=%s", k, lambdaInputs.get(k)))
                                        .toList();
                        var inputs = String.join(", ", inputsInOrder);
                        lambda = lambda + "(" + inputs + ")";
                    }

                    var processStateEvents = new HashSet<>(basicState.getEvents().keySet());

                    if (basicState.getParent() != null) {
                        processStateEvents.addAll(
                                ((BasicState) stateMachine.get(basicState.getParent()))
                                        .getEvents()
                                        .keySet());
                    }
                    processStateMap
                            .computeIfAbsent(lambda, k -> new ArrayList<>())
                            .add(new StateAndEvents(key, processStateEvents));
                }
            } else if (state instanceof NestedJourneyInvokeState nestedState) {
                var nestedStateMachine =
                        nestedState.getNestedJourneyDefinition().getNestedJourneyStates();
                findProcessStatesAndEvents(nestedStateMachine, processStateMap);
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
                    var context = (String) pageStepResponse.value().get("context");

                    if (context != null) {
                        pageId += context;
                    }

                    var pageEvents = new HashSet<>(basicState.getEvents().keySet());
                    pageEvents.remove(
                            "back"); // the back event is a special case that may or may not be
                    // defined
                    if (basicState.getParent() != null) {
                        pageEvents.addAll(
                                ((BasicState) stateMachine.get(basicState.getParent()))
                                        .getEvents()
                                        .keySet());
                    }
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
