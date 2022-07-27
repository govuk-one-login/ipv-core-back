package uk.gov.di.ipv.core.journeyengine.statemachine;

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

    public Map<String, State> initialize() throws IOException {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        File file =
                new File(
                        Objects.requireNonNull(classLoader.getResource("statemachine-config.yaml"))
                                .getFile());

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
}
