package uk.gov.di.ipv.core.processjourneystep.statemachine;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.SubJourneyDefinition;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.SubJourneyInvokeState;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;

public class StateMachineInitializer {
    private static final ObjectMapper om = new ObjectMapper(new YAMLFactory());
    private static final ObjectMapper jsonOm = new ObjectMapper();
    private final IpvJourneyTypes journeyType;

    public StateMachineInitializer(IpvJourneyTypes journeyType) {
        this.journeyType = journeyType;
    }

    public Map<String, State> initialize() throws IOException {
        Map<String, State> journeyStates =
                om.readValue(getJourneyConfigFile(journeyType), new TypeReference<>() {});
        Map<String, SubJourneyDefinition> subJourneys =
                om.readValue(getSubJourneyConfigFile(), new TypeReference<>() {});

        subJourneys.forEach(
                (subJourneyName, subJourney) -> {
                    subJourney
                            .getSubJourneyStates()
                            .forEach(
                                    (stateName, state) -> {
                                        if (state instanceof BasicState) {
                                            //                                    ((BasicState)
                                            // state).setName(String.format("%s/%s", subJourneyName,
                                            // stateName));
                                            if (((BasicState) state).getParent() != null) {
                                                ((BasicState) state)
                                                        .setParentObj(
                                                                (BasicState)
                                                                        journeyStates.get(
                                                                                ((BasicState) state)
                                                                                        .getParent()));
                                            }
                                            ((BasicState) state)
                                                    .getEvents()
                                                    .forEach(
                                                            (eventName, event) ->
                                                                    event.initialize(
                                                                            eventName,
                                                                            subJourney
                                                                                    .getSubJourneyStates()));
                                        }

                                        if (state instanceof SubJourneyInvokeState) {
                                            ((SubJourneyInvokeState) state)
                                                    .setSubJourneyDefinition(
                                                            subJourneys.get(
                                                                    ((SubJourneyInvokeState) state)
                                                                            .getSubJourney()));
                                            ((SubJourneyInvokeState) state)
                                                    .getExitEvents()
                                                    .forEach(
                                                            (eventName, event) ->
                                                                    event.initialize(
                                                                            eventName,
                                                                            journeyStates));
                                        }
                                    });
                });

        journeyStates.forEach(
                (stateName, state) -> {
                    if (state instanceof BasicState) {
                        ((BasicState) state).setName(stateName);
                        if (((BasicState) state).getParent() != null) {
                            ((BasicState) state)
                                    .setParentObj(
                                            (BasicState)
                                                    journeyStates.get(
                                                            ((BasicState) state).getParent()));
                        }
                        ((BasicState) state)
                                .getEvents()
                                .forEach(
                                        (eventName, event) ->
                                                event.initialize(eventName, journeyStates));
                    }

                    if (state instanceof SubJourneyInvokeState) {
                        state.setName(stateName);
                        SubJourneyDefinition subJourneyDefinition =
                                subJourneys.get(((SubJourneyInvokeState) state).getSubJourney());
                        SubJourneyDefinition deepCopy;
                        try {
                            deepCopy =
                                    jsonOm.readValue(
                                            jsonOm.writeValueAsString(subJourneyDefinition),
                                            SubJourneyDefinition.class);
                        } catch (JsonProcessingException e) {
                            throw new RuntimeException(e);
                        }
                        deepCopy.getSubJourneyStates()
                                .forEach(
                                        (subJourneyStateName, subJourneyState) -> {
                                            subJourneyState.setName(
                                                    String.format(
                                                            "%s/%s",
                                                            state.getName(), subJourneyStateName));
                                            if (subJourneyState instanceof BasicState) {
                                                ((BasicState) subJourneyState)
                                                        .getEvents()
                                                        .forEach(
                                                                (eventName, event) -> {
                                                                    event.initialize(
                                                                            eventName,
                                                                            deepCopy
                                                                                    .getSubJourneyStates());
                                                                });
                                            }
                                        });
                        ((SubJourneyInvokeState) state).setSubJourneyDefinition(deepCopy);
                        ((SubJourneyInvokeState) state)
                                .getExitEvents()
                                .forEach(
                                        (eventName, event) ->
                                                event.initialize(eventName, journeyStates));
                    }
                });

        return journeyStates;
    }

    private File getJourneyConfigFile(IpvJourneyTypes journeyType) {
        return getFile(journeyType.getValue());
    }

    private File getSubJourneyConfigFile() {
        return getFile("sub-journeys");
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
