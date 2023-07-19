package uk.gov.di.ipv.core.processjourneystep.statemachine;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.Event;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.SubJourneyDefinition;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.SubJourneyInvokeState;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;

public class StateMachineInitializer {
    private static final ObjectMapper yamlOm = new ObjectMapper(new YAMLFactory());
    private static final ObjectMapper om = new ObjectMapper();
    private final IpvJourneyTypes journeyType;

    public StateMachineInitializer(IpvJourneyTypes journeyType) {
        this.journeyType = journeyType;
    }

    public Map<String, State> initialize() throws IOException {
        Map<String, State> journeyStates =
                yamlOm.readValue(getJourneyConfigFile(journeyType), new TypeReference<>() {});
        Map<String, SubJourneyDefinition> subJourneyDefinitions =
                yamlOm.readValue(getSubJourneyDefinitionsConfigFile(), new TypeReference<>() {});

        initializeJourneyStates(journeyStates, subJourneyDefinitions);

        return journeyStates;
    }

    private void initializeJourneyStates(
            Map<String, State> journeyStates,
            Map<String, SubJourneyDefinition> subJourneyDefinitions) {
        journeyStates.forEach(
                (stateName, state) -> {
                    if (state instanceof BasicState) {
                        BasicState basicState = (BasicState) state;
                        basicState.setName(stateName);
                        linkBasicStateParents(basicState, journeyStates);
                        initializeBasicStateEvents(basicState, journeyStates);
                    }

                    if (state instanceof SubJourneyInvokeState) {
                        SubJourneyInvokeState subJourneyInvokeState = (SubJourneyInvokeState) state;
                        subJourneyInvokeState.setName(stateName);
                        SubJourneyDefinition subJourneyDefinition =
                                subJourneyDefinitions.get(subJourneyInvokeState.getSubJourney());
                        SubJourneyDefinition subJourneyDefinitionCopy =
                                deepCopySubJourneyDefinition(subJourneyDefinition);
                        subJourneyInvokeState.setSubJourneyDefinition(
                                initializeSubJourneyDefinition(
                                        subJourneyInvokeState, subJourneyDefinitionCopy, journeyStates, subJourneyDefinitions));
                        initializeExitStateEvents(subJourneyInvokeState, journeyStates);
                    }
                });
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

    private void linkBasicStateParents(BasicState state, Map<String, State> journeyStates) {
        if (state.getParent() != null) {
            state.setParentObj((BasicState) journeyStates.get(state.getParent()));
        }
    }

    private void initializeBasicStateEvents(
            BasicState state, Map<String, State> eventStatesSource) {
        initializeEvents(state.getEvents(), eventStatesSource);
    }

    private void initializeExitStateEvents(
            SubJourneyInvokeState state, Map<String, State> eventStatesSource) {
        initializeEvents(state.getExitEvents(), eventStatesSource);
    }

    private void initializeEvents(
            Map<String, Event> eventMap, Map<String, State> eventStatesSource) {
        eventMap.forEach((eventName, event) -> event.initialize(eventName, eventStatesSource));
    }

    private String createSubJourneyStateName(State state, String subJourneyStateName) {
        return String.format("%s/%s", state.getName(), subJourneyStateName);
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
            SubJourneyDefinition subJourneyDefinition,
            Map<String, State> journeyStates,
            Map<String, SubJourneyDefinition> subJourneyDefinitions) {
        subJourneyDefinition
                .getSubJourneyStates()
                .forEach(
                        (subJourneyStateName, subJourneyState) -> {
                            subJourneyState.setName(
                                    createSubJourneyStateName(
                                            subJourneyInvokeState, subJourneyStateName));
                            if (subJourneyState instanceof BasicState) {
                                BasicState basicState = (BasicState) subJourneyState;
                                linkBasicStateParents(basicState, journeyStates);
                                initializeBasicStateEvents(
                                        (BasicState) subJourneyState,
                                        subJourneyDefinition.getSubJourneyStates());
                            }
                            if (subJourneyState instanceof SubJourneyInvokeState) {
                                SubJourneyInvokeState innerSubJourneyInvokeState =
                                        (SubJourneyInvokeState) subJourneyState;
                                SubJourneyDefinition innerSubJourneyDefinition = subJourneyDefinitions.get(innerSubJourneyInvokeState.getSubJourney());
                                SubJourneyDefinition innerSubJourneyDefinitionCopy =
                                        deepCopySubJourneyDefinition(innerSubJourneyDefinition);

                                innerSubJourneyInvokeState.setSubJourneyDefinition(
                                        initializeSubJourneyDefinition(
                                                innerSubJourneyInvokeState, innerSubJourneyDefinitionCopy, subJourneyDefinition.getSubJourneyStates(), subJourneyDefinitions));
                                initializeExitStateEvents(
                                        innerSubJourneyInvokeState,
                                        subJourneyDefinition.getSubJourneyStates());
                            }
                        });

        return subJourneyDefinition;
    }
}
