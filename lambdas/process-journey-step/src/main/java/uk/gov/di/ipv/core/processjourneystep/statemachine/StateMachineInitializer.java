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
    private static final String PRODUCTION_CONFIG_FILE_PATH =
            "statemachine/production/ipv-core-main-journey.yaml";

    private final String environment;
    private final IpvJourneyTypes journeyType;

    public StateMachineInitializer(String environment, IpvJourneyTypes journeyType) {
        this.environment = environment;
        this.journeyType = journeyType;
    }

    public Map<String, State> initialize() throws IOException {
        File file = getConfigFile(environment, journeyType);

        ObjectMapper om = new ObjectMapper(new YAMLFactory());

        Map<String, State> states = om.readValue(file, new TypeReference<>() {});

        states.forEach(
                (stateName, state) -> {
                    if (state.getParent() != null) {
                        state.setParent(states.get(state.getParent().getName()));
                    }
                });

        return states;
    }

    private File getConfigFile(String environment, IpvJourneyTypes journeyType) {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

        if (journeyType.equals(IpvJourneyTypes.IPV_CORE_REFACTOR_JOURNEY)) {
            return new File(
                    Objects.requireNonNull(
                                    classLoader.getResource(
                                            String.format(
                                                    "statemachine/%s.yaml",
                                                    journeyType.getValue())))
                            .getFile());
        }

        if (environment.contains("dev-")) {
            return new File(
                    Objects.requireNonNull(
                                    classLoader.getResource(
                                            String.format(
                                                    "statemachine/dev/%s.yaml",
                                                    journeyType.getValue())))
                            .getFile());
        }

        String fileName =
                String.format("statemachine/%s/%s.yaml", environment, journeyType.getValue());
        return new File(
                Objects.requireNonNullElse(
                                classLoader.getResource(fileName),
                                classLoader.getResource(PRODUCTION_CONFIG_FILE_PATH))
                        .getFile());
    }
}
