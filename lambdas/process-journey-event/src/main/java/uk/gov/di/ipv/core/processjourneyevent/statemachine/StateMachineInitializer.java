package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import com.amazonaws.util.IOUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.ExitNestedJourneyEvent;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.JourneyMapDeserializationException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyDefinition;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyInvokeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

public class StateMachineInitializer {
    private static final ObjectMapper yamlOm = new ObjectMapper(new YAMLFactory());
    private static final ObjectMapper om = new ObjectMapper();
    private Map<String, State> journeyStates;
    private Map<String, NestedJourneyDefinition> nestedJourneyDefinitions;
    private final StateMachineInitializerMode mode;

    public StateMachineInitializer(IpvJourneyTypes journeyType) {
        this(journeyType, StateMachineInitializerMode.STANDARD);
    }

    public StateMachineInitializer(IpvJourneyTypes journeyType, StateMachineInitializerMode mode) {
        this.journeyType = journeyType;
        this.mode = mode;
    }

    private final IpvJourneyTypes journeyType;

    public Map<String, State> initialize() throws IOException {
        journeyStates = yamlOm.readValue(getJourneyConfig(journeyType), new TypeReference<>() {});
        nestedJourneyDefinitions =
                yamlOm.readValue(getNestedJourneyDefinitionsConfig(), new TypeReference<>() {});

        initializeJourneyStates();

        return journeyStates;
    }

    private void initializeJourneyStates() {
        journeyStates.forEach(
                (stateName, state) -> {
                    if (state instanceof BasicState basicState) {
                        initializeBasicState(basicState, stateName, journeyStates);
                    }

                    if (state instanceof NestedJourneyInvokeState nestedJourneyInvokeState) {
                        initializeNestedJourneyInvokeState(
                                nestedJourneyInvokeState, stateName, journeyStates);
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
            Map<String, Event> nestedJourneyExitEvents) {
        state.setName(stateName);
        linkBasicStateParents(state, journeyStates);
        initializeBasicStateEvents(state, eventTargetsStatesMap, nestedJourneyExitEvents);
    }

    private void linkBasicStateParents(BasicState state, Map<String, State> journeyStates) {
        if (state.getParent() != null) {
            state.setParentObj((BasicState) journeyStates.get(state.getParent()));
        }
    }

    private void initializeBasicStateEvents(
            BasicState state,
            Map<String, State> eventStatesSource,
            Map<String, Event> nestedJourneyExitEvents) {
        initializeEvents(state.getEvents(), eventStatesSource, nestedJourneyExitEvents);
    }

    private void initializeEvents(
            Map<String, Event> eventMap,
            Map<String, State> eventStatesSource,
            Map<String, Event> nestedJourneyExitEvents) {
        eventMap.forEach(
                (eventName, event) -> {
                    if (event instanceof ExitNestedJourneyEvent exitNestedJourneyEvent) {
                        exitNestedJourneyEvent.setNestedJourneyExitEvents(nestedJourneyExitEvents);
                    } else {
                        event.initialize(eventName, eventStatesSource);
                    }
                });
    }

    void initializeNestedJourneyInvokeState(
            NestedJourneyInvokeState state, String stateName, Map<String, State> journeyStates) {
        state.setName(stateName);
        NestedJourneyDefinition nestedJourneyDefinition =
                nestedJourneyDefinitions.get(state.getNestedJourney());
        NestedJourneyDefinition nestedJourneyDefinitionCopy =
                deepCopyNestedJourneyDefinition(nestedJourneyDefinition);
        state.setNestedJourneyDefinition(
                initializeNestedJourneyDefinition(state, nestedJourneyDefinitionCopy));
        initializeExitStateEvents(state, journeyStates);
    }

    private NestedJourneyDefinition deepCopyNestedJourneyDefinition(
            NestedJourneyDefinition toCopy) {
        try {
            return om.readValue(om.writeValueAsString(toCopy), NestedJourneyDefinition.class);
        } catch (JsonProcessingException e) {
            throw new JourneyMapDeserializationException(e);
        }
    }

    private NestedJourneyDefinition initializeNestedJourneyDefinition(
            NestedJourneyInvokeState nestedJourneyInvokeState,
            NestedJourneyDefinition nestedJourneyDefinition) {

        nestedJourneyDefinition
                .getNestedJourneyStates()
                .forEach(
                        (nestedJourneyStateName, nestedJourneyState) -> {
                            String name =
                                    createNestedJourneyStateName(
                                            nestedJourneyInvokeState, nestedJourneyStateName);
                            if (nestedJourneyState instanceof BasicState basicState) {
                                initializeBasicState(
                                        basicState,
                                        name,
                                        nestedJourneyDefinition.getNestedJourneyStates(),
                                        nestedJourneyInvokeState.getExitEvents());
                            }
                            if (nestedJourneyState
                                    instanceof
                                    NestedJourneyInvokeState
                                    subNestedJourneyInvokeState) {
                                initializeNestedJourneyInvokeState(
                                        subNestedJourneyInvokeState,
                                        name,
                                        nestedJourneyDefinition.getNestedJourneyStates());
                            }
                        });
        initializeEvents(
                nestedJourneyDefinition.getEntryEvents(),
                nestedJourneyDefinition.getNestedJourneyStates(),
                null);

        return nestedJourneyDefinition;
    }

    private void initializeExitStateEvents(
            NestedJourneyInvokeState state, Map<String, State> eventStatesSource) {
        initializeEvents(state.getExitEvents(), eventStatesSource, null);
    }

    private String createNestedJourneyStateName(State state, String nestedJourneyStateName) {
        return String.format("%s/%s", state.getName(), nestedJourneyStateName);
    }

    private String getJourneyConfig(IpvJourneyTypes journeyType) throws IOException {
        return readFileToString(journeyType.getPath());
    }

    private String getNestedJourneyDefinitionsConfig() throws IOException {
        return readFileToString("nested-journey-definitions");
    }

    private String readFileToString(String filename) throws IOException {
        InputStream inputStream =
                getClass()
                        .getClassLoader()
                        .getResourceAsStream(
                                String.format(
                                        "statemachine/%s%s.yaml", mode.getPathPart(), filename));

        if (inputStream == null) {
            throw new JourneyMapDeserializationException("Could not find journey map");
        }

        return IOUtils.toString(inputStream);
    }
}
