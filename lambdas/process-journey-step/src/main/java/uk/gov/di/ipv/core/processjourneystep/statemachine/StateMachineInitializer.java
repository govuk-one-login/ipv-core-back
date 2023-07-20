package uk.gov.di.ipv.core.processjourneystep.statemachine;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.ExitEvent;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.SubJourneyInvokeState;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;

public class StateMachineInitializer {
    private static final ObjectMapper yamlOm = new ObjectMapper(new YAMLFactory());
    private static final ObjectMapper om = new ObjectMapper();
    private static Map<String, State> journeyStates;
    private static Map<String, SubJourneyDefinition> subJourneyDefinitions;

    public StateMachineInitializer(IpvJourneyTypes journeyType) {
        this.journeyType = journeyType;
    }

    private final IpvJourneyTypes journeyType;

    public Map<String, State> initialize() throws IOException {
        journeyStates =
                yamlOm.readValue(getJourneyConfigFile(journeyType), new TypeReference<>() {});
        subJourneyDefinitions =
                yamlOm.readValue(getSubJourneyDefinitionsConfigFile(), new TypeReference<>() {});

        initializeJourneyStates();

        return journeyStates;
    }

    private void initializeJourneyStates() {
        journeyStates.forEach(
                (stateName, state) -> {
                    if (state instanceof BasicState) {
                        initializeBasicState((BasicState) state, stateName, journeyStates);
                    }

                    if (state instanceof SubJourneyInvokeState) {
                        initializeSubJourneyInvokeState(
                                (SubJourneyInvokeState) state, stateName, journeyStates);
                    }
                });
    }

    void initializeBasicState(
            BasicState state, String stateName, Map<String, State> eventTargetsStatesMap) {
        initializeBasicState(state, stateName, eventTargetsStatesMap, null);
    }

    void initializeBasicState(
            BasicState state,
            String stateName,
            Map<String, State> eventTargetsStatesMap,
            Map<String, Event> subJourneyExitEvents) {
        state.setName(stateName);
        linkBasicStateParents(state, journeyStates);
        initializeBasicStateEvents(state, eventTargetsStatesMap, subJourneyExitEvents);
    }

    private void linkBasicStateParents(BasicState state, Map<String, State> journeyStates) {
        if (state.getParent() != null) {
            state.setParentObj((BasicState) journeyStates.get(state.getParent()));
        }
    }

    private void initializeBasicStateEvents(
            BasicState state,
            Map<String, State> eventStatesSource,
            Map<String, Event> subJourneyExitEvents) {
        initializeEvents(state.getEvents(), eventStatesSource, subJourneyExitEvents);
    }

    private void initializeEvents(
            Map<String, Event> eventMap,
            Map<String, State> eventStatesSource,
            Map<String, Event> subJourneyExitEvents) {
        eventMap.forEach(
                (eventName, event) -> {
                    if (event instanceof ExitEvent) {
                        ((ExitEvent) event).setSubJourneyExitEvents(subJourneyExitEvents);
                    } else {
                        event.initialize(eventName, eventStatesSource);
                    }
                });
    }

    void initializeSubJourneyInvokeState(
            SubJourneyInvokeState state, String stateName, Map<String, State> journeyStates) {
        state.setName(stateName);
        SubJourneyDefinition subJourneyDefinition =
                subJourneyDefinitions.get(state.getSubJourney());
        SubJourneyDefinition subJourneyDefinitionCopy =
                deepCopySubJourneyDefinition(subJourneyDefinition);
        state.setSubJourneyDefinition(
                initializeSubJourneyDefinition(state, subJourneyDefinitionCopy));
        initializeExitStateEvents(state, journeyStates);
    }

    private SubJourneyDefinition deepCopySubJourneyDefinition(SubJourneyDefinition toCopy) {
        try {
            return om.readValue(om.writeValueAsString(toCopy), SubJourneyDefinition.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private SubJourneyDefinition initializeSubJourneyDefinition(
            SubJourneyInvokeState subJourneyInvokeState,
            SubJourneyDefinition subJourneyDefinition) {

        subJourneyDefinition
                .getSubJourneyStates()
                .forEach(
                        (subJourneyStateName, subJourneyState) -> {
                            String name =
                                    createSubJourneyStateName(
                                            subJourneyInvokeState, subJourneyStateName);
                            if (subJourneyState instanceof BasicState) {
                                initializeBasicState(
                                        (BasicState) subJourneyState,
                                        name,
                                        subJourneyDefinition.getSubJourneyStates(),
                                        subJourneyInvokeState.getExitEvents());
                            }
                            if (subJourneyState instanceof SubJourneyInvokeState) {
                                initializeSubJourneyInvokeState(
                                        (SubJourneyInvokeState) subJourneyState,
                                        name,
                                        subJourneyDefinition.getSubJourneyStates());
                            }
                        });
        initializeEvents(
                subJourneyDefinition.getEntryEvents(),
                subJourneyDefinition.getSubJourneyStates(),
                null);

        return subJourneyDefinition;
    }

    private void initializeExitStateEvents(
            SubJourneyInvokeState state, Map<String, State> eventStatesSource) {
        initializeEvents(state.getExitEvents(), eventStatesSource, null);
    }

    private String createSubJourneyStateName(State state, String subJourneyStateName) {
        return String.format("%s/%s", state.getName(), subJourneyStateName);
    }

    private File getJourneyConfigFile(IpvJourneyTypes journeyType) {
        return getFile(journeyType.getValue());
    }

    private File getSubJourneyDefinitionsConfigFile() {
        return getFile("sub-journey-definitions");
    }

    private File getFile(String filename) {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        return new File(
                Objects.requireNonNull(
                                classLoader.getResource(
                                        String.format("statemachine/%s.yaml", filename)))
                        .getFile());
    }
}
