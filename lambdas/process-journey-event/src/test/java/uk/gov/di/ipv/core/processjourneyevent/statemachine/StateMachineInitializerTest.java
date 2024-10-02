package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import com.fasterxml.jackson.databind.JsonMappingException;
import org.junit.jupiter.api.Test;
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

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.INITIAL_JOURNEY_SELECTION;

class StateMachineInitializerTest {
    private static final List<String> TEST_NESTED_JOURNEY_TYPES =
            List.of("nested-journey-definition", "doubly-nested-definition");

    @ParameterizedTest
    @EnumSource
    void stateMachineInitializerShouldHandleAllProductionJourneyMaps(IpvJourneyTypes journeyType) {
        assertDoesNotThrow(() -> new StateMachineInitializer(journeyType).initialize());
    }

    @Test
    void initializeShouldThrowIfJourneyMapNotFound() {
        StateMachineInitializerMode modeMock = mock(StateMachineInitializerMode.class);
        when(modeMock.getPathPart()).thenReturn("some-rubbish");
        StateMachineInitializer initializer =
                new StateMachineInitializer(
                        INITIAL_JOURNEY_SELECTION, modeMock, TEST_NESTED_JOURNEY_TYPES);
        assertThrows(JourneyMapDeserializationException.class, initializer::initialize);
    }

    @Test
    void initializeShouldThrowIfJourneyMapHasDuplicateKeys() {
        var journeyTypeMock = mock(IpvJourneyTypes.class);
        when(journeyTypeMock.getPath()).thenReturn("journey-map-with-duplicate-keys");

        var stateMachineInitializer =
                new StateMachineInitializer(
                        journeyTypeMock,
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES);

        var jsonMappingException =
                assertThrows(JsonMappingException.class, stateMachineInitializer::initialize);

        assertTrue(jsonMappingException.getMessage().contains("Duplicate field 'DUPLICATE_PAGE'"));
    }

    @java.lang.SuppressWarnings("java:S5961") // Too many assertions
    @Test
    void stateMachineInitializerShouldCorrectlyDeserializeJourneyMaps() throws IOException {
        Map<String, State> journeyMap =
                new StateMachineInitializer(
                                INITIAL_JOURNEY_SELECTION,
                                StateMachineInitializerMode.TEST,
                                TEST_NESTED_JOURNEY_TYPES)
                        .initialize();

        State parentState = journeyMap.get("PARENT_STATE");
        BasicState pageState = (BasicState) journeyMap.get("PAGE_STATE");
        BasicState anotherPageState = (BasicState) journeyMap.get("ANOTHER_PAGE_STATE");
        BasicState criState = (BasicState) journeyMap.get("CRI_STATE");
        BasicState criWithContextState = (BasicState) journeyMap.get("CRI_STATE_WITH_CONTEXT");
        BasicState criWithEvidenceRequest =
                (BasicState) journeyMap.get("CRI_STATE_WITH_EVIDENCE_REQUEST");
        BasicState criWithContextAndEvidenceRequest =
                (BasicState) journeyMap.get("CRI_STATE_WITH_CONTEXT_AND_EVIDENCE_REQUEST");
        BasicState errorState = (BasicState) journeyMap.get("ERROR_STATE");
        BasicState processState = (BasicState) journeyMap.get("PROCESS_STATE");
        NestedJourneyInvokeState nestedJourneyInvokeState =
                (NestedJourneyInvokeState) journeyMap.get("NESTED_JOURNEY_INVOKE_STATE");

        // page state assertions
        assertEquals("page-id-for-page-state", pageState.getResponse().value().get("page"));
        assertEquals(parentState, pageState.getParentObj());
        assertEquals(INITIAL_JOURNEY_SELECTION, pageState.getJourneyType());
        assertEquals(
                anotherPageState,
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
                "/journey/cri/build-oauth-request/aCriId?evidenceRequest=eyJzY29yaW5nUG9saWN5IjoiZ3BnNDUiLCJzdHJlbmd0aFNjb3JlIjoyfQ%3D%3D",
                criWithEvidenceRequest.getResponse().value().get("journey"));

        // cri state with context and scope assertion
        assertEquals(
                "/journey/cri/build-oauth-request/aCriId?context=test_context&evidenceRequest=eyJzY29yaW5nUG9saWN5IjoiZ3BnNDUiLCJzdHJlbmd0aFNjb3JlIjoyfQ%3D%3D",
                criWithContextAndEvidenceRequest.getResponse().value().get("journey"));

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
        assertEquals(INITIAL_JOURNEY_SELECTION, pageState.getJourneyType());
        assertEquals(
                anotherPageState,
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
        assertEquals("page-id-nested-state-one", nestedStateOne.getResponse().value().get("page"));
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
                "page-id-doubly-nested-state-one",
                doublyNestedStateOne.getResponse().value().get("page"));
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
