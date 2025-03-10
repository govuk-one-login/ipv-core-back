package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.ExitNestedJourneyEvent;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.JourneyMapDeserializationException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.Journey;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyDefinition;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyInvokeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION;

public class StateMachineInitializer {
    private static final String NESTED_JOURNEYS_SUBFOLDER = "nested-journeys";

    private static final ObjectMapper yamlOm =
            new ObjectMapper(new YAMLFactory()).configure(STRICT_DUPLICATE_DETECTION, true);
    private static final ObjectMapper om = new ObjectMapper();
    private Map<String, State> journeyStates;
    private Map<String, NestedJourneyDefinition> nestedJourneyDefinitions;
    private final StateMachineInitializerMode mode;
    private final List<String> nestedJourneyTypes;

    public StateMachineInitializer(IpvJourneyTypes journeyType) {
        this(
                journeyType,
                StateMachineInitializerMode.STANDARD,
                Stream.of(NestedJourneyTypes.values())
                        .map(NestedJourneyTypes::getJourneyName)
                        .toList());
    }

    public StateMachineInitializer(
            IpvJourneyTypes journeyType,
            StateMachineInitializerMode mode,
            List<String> nestedJourneyTypes) {
        this.journeyType = journeyType;
        this.mode = mode;
        this.nestedJourneyTypes = nestedJourneyTypes;
    }

    private final IpvJourneyTypes journeyType;

    public Map<String, State> initialize() throws IOException {
        Journey journey =
                yamlOm.readValue(getJourneyConfig(journeyType.getPath()), new TypeReference<>() {});
        journeyStates = journey.states();
        nestedJourneyDefinitions = getNestedJourneysFromConfig();

        initializeJourneyStates();

        return journeyStates;
    }

    private void initializeJourneyStates() {
        journeyStates.forEach(
                (stateName, state) -> {
                    if (state instanceof BasicState basicState) {
                        initializeBasicState(basicState, stateName, journeyStates, null);
                    }

                    if (state instanceof NestedJourneyInvokeState nestedJourneyInvokeState) {
                        initializeNestedJourneyInvokeState(
                                nestedJourneyInvokeState, stateName, journeyStates, null);
                    }
                });
    }

    void initializeBasicState(
            BasicState state,
            String stateName,
            Map<String, State> eventTargetsStatesMap,
            Map<String, Event> nestedJourneyExitEvents) {
        state.setName(stateName);
        state.setJourneyType(journeyType);
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
                        event.initialize(eventName, eventStatesSource, nestedJourneyExitEvents);
                    }
                });
    }

    void initializeNestedJourneyInvokeState(
            NestedJourneyInvokeState state,
            String stateName,
            Map<String, State> journeyStates,
            Map<String, Event> nestedJourneyExitEvents) {
        state.setName(stateName);
        state.setJourneyType(journeyType);
        state.setNestedJourneyDefinition(
                initializeNestedJourneyDefinition(
                        state,
                        deepCopyNestedJourneyDefinition(
                                nestedJourneyDefinitions.get(state.getNestedJourney()))));
        initializeExitStateEvents(state, journeyStates, nestedJourneyExitEvents);
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
                                    NestedJourneyInvokeState subNestedJourneyInvokeState) {
                                initializeNestedJourneyInvokeState(
                                        subNestedJourneyInvokeState,
                                        name,
                                        nestedJourneyDefinition.getNestedJourneyStates(),
                                        nestedJourneyInvokeState.getExitEvents());
                            }
                        });
        initializeEvents(
                nestedJourneyDefinition.getEntryEvents(),
                nestedJourneyDefinition.getNestedJourneyStates(),
                nestedJourneyInvokeState.getExitEvents());

        return nestedJourneyDefinition;
    }

    private void initializeExitStateEvents(
            NestedJourneyInvokeState state,
            Map<String, State> eventStatesSource,
            Map<String, Event> nestedJourneyExitEvents) {
        initializeEvents(state.getExitEvents(), eventStatesSource, nestedJourneyExitEvents);
    }

    private String createNestedJourneyStateName(
            NestedJourneyInvokeState state, String nestedJourneyStateName) {
        return String.format("%s/%s", state.getName(), nestedJourneyStateName);
    }

    private InputStream getJourneyConfig(String path) {
        var inputStream =
                getClass()
                        .getClassLoader()
                        .getResourceAsStream(
                                String.format("statemachine/%s%s.yaml", mode.getPathPart(), path));

        if (inputStream == null) {
            throw new JourneyMapDeserializationException("Could not find journey map");
        }

        return inputStream;
    }

    private String transformToUpperSnakeCase(String input) {
        return input.toUpperCase().replace("-", "_");
    }

    private Map<String, NestedJourneyDefinition> getNestedJourneysFromConfig() throws IOException {
        var map = new HashMap<String, NestedJourneyDefinition>();
        for (var nestedJourney : nestedJourneyTypes) {
            var path = String.format("%s/%s", NESTED_JOURNEYS_SUBFOLDER, nestedJourney);
            var journeyName = transformToUpperSnakeCase(nestedJourney);
            var journeyDef =
                    yamlOm.readValue(getJourneyConfig(path), NestedJourneyDefinition.class);
            map.put(journeyName, journeyDef);
        }
        return map;
    }
}
