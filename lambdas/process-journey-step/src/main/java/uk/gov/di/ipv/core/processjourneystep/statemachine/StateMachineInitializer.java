package uk.gov.di.ipv.core.processjourneystep.statemachine;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;

@ExcludeFromGeneratedCoverageReport
public class StateMachineInitializer {
    private static final String PRODUCTION_CONFIG_FILE_PATH =
            "statemachine/production-statemachine-config.yaml";

    private final String environment;

    public StateMachineInitializer(String environment) {
        this.environment = environment;
    }

    public Map<String, State> initialize() throws IOException {
        File file = getConfigFile(environment);

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

    private File getConfigFile(String environment) {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (environment.contains("dev-")) {
            return new File(
                    Objects.requireNonNull(
                                    classLoader.getResource(
                                            "statemachine/dev-statemachine-config.yaml"))
                            .getFile());
        }

        String fileName = String.format("statemachine/%s-statemachine-config.yaml", environment);
        return new File(
                Objects.requireNonNullElse(
                                classLoader.getResource(fileName),
                                classLoader.getResource(PRODUCTION_CONFIG_FILE_PATH))
                        .getFile());
    }
}
