package uk.gov.di.ipv.core.processjourneystep.statemachine;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.File;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.IPV_CORE_REFACTOR_JOURNEY;

@ExtendWith(SystemStubsExtension.class)
class StateMachineInitializerTest {

    @SystemStub private EnvironmentVariables environmentVariables;

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void stateMachineInitializerShouldHandleAllStateFiles(String environment) {
        for (IpvJourneyTypes journeyType :
                List.of(IPV_CORE_MAIN_JOURNEY, IPV_CORE_REFACTOR_JOURNEY)) {
            assertDoesNotThrow(() -> new StateMachineInitializer(environment, journeyType));
        }
    }

    // This is to make sure any yaml files not covered by the journey type / envs above are at least
    // loaded.
    @Test
    void allStateMachineFilesShouldLoadWithoutError() throws Exception {
        environmentVariables.set("IS_LOCAL", "true");
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        URL statemachineDir = classLoader.getResource("statemachine");

        List<Path> statemachineFilePaths =
                Files.walk(Paths.get(statemachineDir.toURI()))
                        .filter(Files::isRegularFile)
                        .filter(file -> file.getFileName().toString().endsWith(".yaml"))
                        .collect(Collectors.toList());

        ObjectMapper om = new ObjectMapper(new YAMLFactory());

        for (Path statemachineFile : statemachineFilePaths) {
            assertDoesNotThrow(
                    () -> {
                        Map<String, State> states =
                                om.readValue(
                                        new File(statemachineFile.toUri()),
                                        new TypeReference<>() {});
                    });
        }
    }
}
