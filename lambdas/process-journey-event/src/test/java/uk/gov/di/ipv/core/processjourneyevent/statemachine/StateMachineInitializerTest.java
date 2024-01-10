package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.BasicEvent;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.ExitNestedJourneyEvent;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.JourneyMapDeserializationException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyDefinition;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyInvokeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(SystemStubsExtension.class)
class StateMachineInitializerTest {

    @SystemStub private static EnvironmentVariables environmentVariables;

    @BeforeAll
    private static void beforeAll() {
        environmentVariables.set("IS_LOCAL", "true");
    }

    @ParameterizedTest
    @EnumSource
    void stateMachineInitializerShouldHandleAllProductionJourneyMaps(IpvJourneyTypes journeyType) {
        assertDoesNotThrow(() -> new StateMachineInitializer(journeyType).initialize());
    }

    @Test
    void initializeShouldThrowIfJourneyMapNotFound() {
        StateMachineInitializerMode modeMock = mock(StateMachineInitializerMode.class);
        when(modeMock.getPathPart()).thenReturn("some-rubbish");
        assertThrows(
                JourneyMapDeserializationException.class,
                () -> {
                    new StateMachineInitializer(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY, modeMock)
                            .initialize();
                });
    }

    @java.lang.SuppressWarnings("java:S5961") // Too many assertions
    @Test
    void stateMachineInitializerShouldCorrectlyDeserializeJourneyMaps() throws IOException {
        Map<String, State> journeyMap =
                new StateMachineInitializer(
                                IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY,
                                StateMachineInitializerMode.TEST)
                        .initialize();

        State parentState = journeyMap.get("PARENT_STATE");
        BasicState pageState = (BasicState) journeyMap.get("PAGE_STATE");
        BasicState journeyState = (BasicState) journeyMap.get("JOURNEY_STATE");
        BasicState criState = (BasicState) journeyMap.get("CRI_STATE");
        BasicState criWithContextState = (BasicState) journeyMap.get("CRI_STATE_WITH_CONTEXT");
        BasicState criWithScopeState = (BasicState) journeyMap.get("CRI_STATE_WITH_SCOPE");
        BasicState criWithContextAndScopeState =
                (BasicState) journeyMap.get("CRI_STATE_WITH_CONTEXT_AND_SCOPE");
        BasicState errorState = (BasicState) journeyMap.get("ERROR_STATE");
        BasicState processState = (BasicState) journeyMap.get("PROCESS_STATE");
        NestedJourneyInvokeState nestedJourneyInvokeState =
                (NestedJourneyInvokeState) journeyMap.get("NESTED_JOURNEY_INVOKE_STATE");

        // page state assertions
        assertEquals("page-id-for-some-page", pageState.getResponse().value().get("page"));
        assertEquals(parentState, pageState.getParentObj());
        assertEquals(
                journeyState,
                ((BasicEvent) pageState.getEvents().get("eventOne")).getTargetStateObj());
        assertEquals(
                criState, ((BasicEvent) pageState.getEvents().get("eventTwo")).getTargetStateObj());
        assertEquals(
                errorState,
                ((BasicEvent)
                                ((BasicEvent) pageState.getEvents().get("eventTwo"))
                                        .getCheckIfDisabled()
                                        .get("aCriId"))
                        .getTargetStateObj());

        // journey state assertions
        assertEquals("/journey/letsgosomewhere", journeyState.getResponse().value().get("journey"));
        assertEquals(
                criState,
                ((BasicEvent) journeyState.getEvents().get("eventOne")).getTargetStateObj());
        assertEquals(
                errorState,
                ((BasicEvent)
                                ((BasicEvent) journeyState.getEvents().get("eventOne"))
                                        .getCheckFeatureFlag()
                                        .get("aFeatureFlagName"))
                        .getTargetStateObj());

        // cri state assertions
        assertEquals(
                "/journey/cri/build-oauth-request/aCriId",
                criState.getResponse().value().get("journey"));
        assertEquals(
                nestedJourneyInvokeState,
                ((BasicEvent) criState.getEvents().get("enterNestedJourneyAtStateOne"))
                        .getTargetStateObj());

        // cri state with context assertion
        assertEquals(
                "/journey/cri/build-oauth-request/aCriId?context=test_context",
                criWithContextState.getResponse().value().get("journey"));

        // cri state with scope assertion
        assertEquals(
                "/journey/cri/build-oauth-request/aCriId?scope=test_scope",
                criWithScopeState.getResponse().value().get("journey"));

        // cri state with context and scope assertion
        assertEquals(
                "/journey/cri/build-oauth-request/aCriId?context=test_context&scope=test_scope",
                criWithContextAndScopeState.getResponse().value().get("journey"));

        // error state assertions
        assertEquals(
                Map.of("statusCode", 500, "type", "error", "page", "page-error"),
                errorState.getResponse().value());
        assertEquals(
                nestedJourneyInvokeState,
                ((BasicEvent) errorState.getEvents().get("enterNestedJourneyAtStateTwo"))
                        .getTargetStateObj());

        // process state assertions
        assertEquals(
                Map.of(
                        "journey",
                        "/journey/a-lambda-to-invoke",
                        "lambdaInput",
                        Map.of("input1", "the-first-input", "input2", 2, "input3", true)),
                processState.getResponse().value());
        assertEquals(
                criState, ((BasicEvent) processState.getEvents().get("met")).getTargetStateObj());
        assertEquals(
                errorState,
                ((BasicEvent) processState.getEvents().get("unmet")).getTargetStateObj());

        // nested journey invoke state assertions
        assertEquals(
                journeyState,
                ((BasicEvent)
                                nestedJourneyInvokeState
                                        .getExitEvents()
                                        .get("exitEventFromNestedStateTwo"))
                        .getTargetStateObj());

        NestedJourneyDefinition nestedJourneyDefinition =
                nestedJourneyInvokeState.getNestedJourneyDefinition();
        BasicState nestedStateOne =
                (BasicState)
                        nestedJourneyDefinition.getNestedJourneyStates().get("NESTED_STATE_ONE");
        BasicState nestedStateTwo =
                (BasicState)
                        nestedJourneyDefinition.getNestedJourneyStates().get("NESTED_STATE_TWO");
        NestedJourneyInvokeState doublyNestedInvokeState =
                (NestedJourneyInvokeState)
                        nestedJourneyDefinition
                                .getNestedJourneyStates()
                                .get("DOUBLY_NESTED_INVOKE_STATE");

        // nested journey definition entry event assertions
        assertEquals(
                nestedStateOne,
                ((BasicEvent)
                                nestedJourneyDefinition
                                        .getEntryEvents()
                                        .get("enterNestedJourneyAtStateOne"))
                        .getTargetStateObj());
        assertEquals(
                nestedStateTwo,
                ((BasicEvent)
                                nestedJourneyDefinition
                                        .getEntryEvents()
                                        .get("enterNestedJourneyAtStateTwo"))
                        .getTargetStateObj());

        // nested state one assertions
        assertEquals(
                "/journey/nestedStateOneJourneyStepId",
                nestedStateOne.getResponse().value().get("journey"));
        assertEquals(parentState, nestedStateOne.getParentObj());
        assertEquals(
                nestedStateTwo,
                ((BasicEvent) nestedStateOne.getEvents().get("eventOne")).getTargetStateObj());

        // nested state two assertions
        assertEquals("page-id-nested-state-two", nestedStateTwo.getResponse().value().get("page"));
        assertEquals(
                "exitEventFromNestedStateTwo",
                ((ExitNestedJourneyEvent) nestedStateTwo.getEvents().get("eventOne"))
                        .getExitEventToEmit());
        assertEquals(
                doublyNestedInvokeState,
                ((BasicEvent) nestedStateTwo.getEvents().get("eventTwo")).getTargetStateObj());

        // doubly nested invoke state assertions
        assertEquals(
                "exitEventFromDoublyNestedInvokeState",
                ((ExitNestedJourneyEvent)
                                doublyNestedInvokeState
                                        .getExitEvents()
                                        .get("exitEventFromDoublyNestedStateTwo"))
                        .getExitEventToEmit());

        NestedJourneyDefinition doublyNestedDefinition =
                doublyNestedInvokeState.getNestedJourneyDefinition();
        BasicState doublyNestedStateOne =
                (BasicState)
                        doublyNestedDefinition
                                .getNestedJourneyStates()
                                .get("DOUBLY_NESTED_STATE_ONE");
        BasicState doublyNestedStateTwo =
                (BasicState)
                        doublyNestedDefinition
                                .getNestedJourneyStates()
                                .get("DOUBLY_NESTED_STATE_TWO");

        // doubly nested journey definition entry events assertions
        assertEquals(
                doublyNestedStateOne,
                ((BasicEvent) doublyNestedDefinition.getEntryEvents().get("eventTwo"))
                        .getTargetStateObj());

        // doubly nested state one assertions
        assertEquals(
                "/journey/doublyNestedStateOneJourneyStepId",
                doublyNestedStateOne.getResponse().value().get("journey"));
        assertEquals(
                doublyNestedStateTwo,
                ((BasicEvent) doublyNestedStateOne.getEvents().get("eventOne"))
                        .getTargetStateObj());

        // doubly nested state two assertions
        assertEquals(
                "page-id-doubly-nested-state-two",
                doublyNestedStateTwo.getResponse().value().get("page"));
        assertEquals(
                "exitEventFromDoublyNestedStateTwo",
                ((ExitNestedJourneyEvent) doublyNestedStateTwo.getEvents().get("eventOne"))
                        .getExitEventToEmit());
    }
}
