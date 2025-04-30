package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ScopeConstants;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.BasicEvent;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolveParameters;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolver;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.PageStepResponse;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class BasicStateTest {
    private EventResolveParameters eventResolveParameters;
    private EventResolver eventResolver;

    @BeforeEach
    void setUp() {
        eventResolveParameters =
                new EventResolveParameters(
                        List.of("journeyContext"),
                        new IpvSessionItem(),
                        ClientOAuthSessionItem.builder().scope(ScopeConstants.OPENID).build());

        eventResolver =
                new EventResolver(mock(CimitUtilityService.class), mock(ConfigService.class));
    }

    @Test
    void transitionShouldReturnAStateWithAResponse() throws Exception {
        BasicState targetState = new BasicState();
        PageStepResponse stepResponse = new PageStepResponse("stepId", "context", false);
        targetState.setResponse(stepResponse);

        BasicState currentState = new BasicState();
        BasicEvent currentToTargetEvent = new BasicEvent();
        currentToTargetEvent.setTargetStateObj(targetState);
        currentState.setEvents(Map.of("next", currentToTargetEvent));

        var result =
                currentState.transition(
                        "next", "startState", eventResolveParameters, eventResolver);

        assertEquals(targetState, result.state());
    }

    @Test
    void transitionShouldUseEventsFromParentState() throws Exception {
        BasicEvent parentEvent = new BasicEvent();
        BasicState parentEventTargetState = new BasicState();
        parentEvent.setTargetStateObj(parentEventTargetState);

        BasicState parentState = new BasicState();
        parentState.setEvents(Map.of("parent-event", parentEvent));

        BasicState currentState = new BasicState();
        currentState.setParentObj(parentState);

        var result =
                currentState.transition(
                        "parent-event", "startState", eventResolveParameters, eventResolver);

        assertEquals(parentEventTargetState, result.state());
    }

    @Test
    void transitionShouldReturnThisIfAttemptRecoveryEventReceived() throws Exception {
        var state = new BasicState();

        assertEquals(
                state,
                state.transition(
                                "attempt-recovery",
                                "startState",
                                eventResolveParameters,
                                eventResolver)
                        .state());
    }

    @Test
    void transitionShouldThrowIfEventNotFound() {
        assertThrows(
                UnknownEventException.class,
                () ->
                        new BasicState()
                                .transition(
                                        "unknown-event",
                                        "startState",
                                        eventResolveParameters,
                                        eventResolver));
    }

    @Test
    void toStringShouldReturnName() {
        BasicState state = new BasicState();
        state.setName("Bungle");

        assertEquals("Bungle", state.toString());
    }
}
