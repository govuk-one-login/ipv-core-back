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

import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(SystemStubsExtension.class)
public class JourneyMapPageContextTest {
    @SystemStub private static EnvironmentVariables environmentVariables;

    @BeforeAll
    public static void beforeAll() {
        environmentVariables.set("IS_LOCAL", "true");
    }

    private final HashMap<String, List<String>> acceptedStateContexts =
            new HashMap<>() {
                {
                    put("pyi-suggest-other-options", List.of("no-photo-id"));
                }
            };

    @ParameterizedTest
    @EnumSource
    void shouldHandleSameContextForSamePage(IpvJourneyTypes journeyType) throws IOException {
        var stateMachineInitializer = new StateMachineInitializer(journeyType);
        var stateMachine = stateMachineInitializer.initialize();

        var pagesWithContexts = new ArrayList<PageStepResponse>();
        findPagesWithContexts(stateMachine, pagesWithContexts);

        var invalidContexts = new HashMap<String, List<String>>();

        for (PageStepResponse response : pagesWithContexts) {
            String pageId = response.getPageId();
            String context = response.getContext();

            if (!acceptedStateContexts.get(pageId).contains(context)) {
                invalidContexts.computeIfAbsent(pageId, k -> new ArrayList<>()).add(context);
            }
        }

        assertTrue(
                invalidContexts.isEmpty(),
                String.format(
                        "Some journey map contexts are not currently supported in ipv-core-front: %s",
                        invalidContexts));
    }

    private void findPagesWithContexts(
            Map<String, State> stateMachine, List<PageStepResponse> pageContextMap) {

        for (var key : stateMachine.keySet()) {
            var state = stateMachine.get(key);

            if (state instanceof BasicState basicState) {
                var response = basicState.getResponse();

                if (response instanceof PageStepResponse pageStepResponse) {
                    var context = (String) pageStepResponse.value().get("context");
                    var pageId = (String) pageStepResponse.value().get("page");

                    if (!context.isEmpty() && !pageId.isEmpty()) {
                        pageContextMap.add(pageStepResponse);
                    }
                }
            }
        }
    }
}
