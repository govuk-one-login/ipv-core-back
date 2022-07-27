package uk.gov.di.ipv.core.processjourneystep.statemachine;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;

@ExcludeFromGeneratedCoverageReport
public class StateMachineInitializer {
    private static final String BUILD_ENV = "build";
    private static final String STAGING_ENV = "staging";
    private static final String INTEGRATION_ENV = "integration";

    private ConfigurationService configurationService;

    public StateMachineInitializer(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public Map<String, State> initialize() throws IOException {
        File file =
                getConfigFile(
                        configurationService.getEnvironmentVariable(
                                EnvironmentVariable.ENVIRONMENT));

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

        if (environment.equals(BUILD_ENV)) {
            return new File(
                    Objects.requireNonNull(
                                    classLoader.getResource(
                                            "statemachine/build-statemachine-config.yaml"))
                            .getFile());
        } else if (environment.equals(STAGING_ENV)) {
            return new File(
                    Objects.requireNonNull(
                                    classLoader.getResource(
                                            "statemachine/staging-statemachine-config.yaml"))
                            .getFile());
        } else if (environment.equals(INTEGRATION_ENV)) {
            return new File(
                    Objects.requireNonNull(
                                    classLoader.getResource(
                                            "statemachine/integration-statemachine-config.yaml"))
                            .getFile());
        } else {
            return new File(
                    Objects.requireNonNull(
                                    classLoader.getResource(
                                            "statemachine/production-statemachine-config.yaml"))
                            .getFile());
        }
    }
}
