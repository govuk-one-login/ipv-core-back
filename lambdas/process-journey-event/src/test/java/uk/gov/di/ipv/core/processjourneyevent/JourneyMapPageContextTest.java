package uk.gov.di.ipv.core.processjourneyevent;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.StateMachineInitializer;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.PageStepResponse;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(SystemStubsExtension.class)
public class JourneyMapPageContextTest {
    @SystemStub private static EnvironmentVariables environmentVariables;

    @BeforeAll
    public static void beforeAll() {
        environmentVariables.set("IS_LOCAL", "true");
    }

    private final HashMap<String, List<String>> expectedStateContexts =
            new HashMap<>() {
                {
                    put("no-photo-id", List.of("MITIGATION_02_OPTIONS_WITH_F2F_J7"));
                }
            };

    @ParameterizedTest
    @EnumSource
    void shouldHandleSameContextForSamePage(IpvJourneyTypes journeyType) throws IOException {
        var stateMachineInitializer = new StateMachineInitializer(journeyType);
        var stateMachine = stateMachineInitializer.initialize();

        var pageContextMap = new HashMap<String, List<StateAndEvents>>();
        findPageSpecificContexts(stateMachine, pageContextMap);

        var missingContexts = new HashMap<>();

        for (var expectedContext : expectedStateContexts.keySet()) {

            for (var expectedEvent : expectedStateContexts.get(expectedContext)) {

                List<StateAndEvents> journeyMapEvent = pageContextMap.get(expectedContext);

                boolean expectedContextIsPresent =
                        journeyMapEvent != null
                                && journeyMapEvent.stream()
                                        .anyMatch(
                                                listEvent -> listEvent.state.equals(expectedEvent));

                if (!expectedContextIsPresent) {
                    missingContexts.put(expectedEvent, expectedContext);
                }
            }
        }

        assertTrue(
                missingContexts.isEmpty(),
                String.format(
                        "ipv-core-front is missing some expected contexts: %s", missingContexts));
    }

    private void findPageSpecificContexts(
            Map<String, State> stateMachine, HashMap<String, List<StateAndEvents>> pageContextMap) {

        for (var key : stateMachine.keySet()) {
            var state = stateMachine.get(key);

            if (state instanceof BasicState basicState) {
                var response = basicState.getResponse();

                if (response instanceof PageStepResponse pageStepResponse) {
                    var context = (String) pageStepResponse.value().get("context");
                    var pageEvents = basicState.getEvents().keySet();

                    pageContextMap
                            .computeIfAbsent(context, k -> new ArrayList<>())
                            .add(new StateAndEvents(key, pageEvents));
                }
            }
        }
    }

    public record StateAndEvents(String state, Set<String> events) {}
}
