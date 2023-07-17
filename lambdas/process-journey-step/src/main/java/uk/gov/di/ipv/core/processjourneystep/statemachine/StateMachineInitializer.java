package uk.gov.di.ipv.core.processjourneystep.statemachine;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;

public class StateMachineInitializer {
    private static final ObjectMapper om = new ObjectMapper(new YAMLFactory());
    private final IpvJourneyTypes journeyType;

    public StateMachineInitializer(IpvJourneyTypes journeyType) {
        this.journeyType = journeyType;
    }

    public Map<String, State> initialize() throws IOException {
        File file = getConfigFile(journeyType);
        Map<String, State> states = om.readValue(file, new TypeReference<>() {});

        states.forEach(
                (stateName, state) -> {
                    if (state.getParent() != null) {
                        state.setParent(states.get(state.getParent().getName()));
                    }
                    state.getEvents()
                            .forEach((eventName, event) -> event.initialize(eventName, states));
                });

        return states;
    }

    private File getConfigFile(IpvJourneyTypes journeyType) {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        return new File(
                Objects.requireNonNull(
                                classLoader.getResource(
                                        String.format(
                                                "statemachine/%s.yaml", journeyType.getValue())))
                        .getFile());
    }
}
