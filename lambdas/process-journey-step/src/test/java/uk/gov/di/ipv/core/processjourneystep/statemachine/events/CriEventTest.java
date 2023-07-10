package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneystep.statemachine.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyResponse;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.PageResponse;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class CriEventTest {

    @SystemStub private EnvironmentVariables environmentVariables;

    @Mock private ConfigService mockConfigService;

    @Test
    void resolveShouldReturnAStateMachineResult() {
        State state = new State("sausages");

        CriEvent criEvent = new CriEvent(mockConfigService);
        criEvent.setTargetState(state);
        criEvent.setCriId("aCriId");

        StateMachineResult result = criEvent.resolve(JourneyContext.emptyContext());

        assertEquals(state, result.getState());
        assertEquals(
                "/journey/cri/build-oauth-request/aCriId",
                result.getJourneyStepResponse().value(mockConfigService).get("journey"));
    }

    @Test
    void resolveShouldReturnAlternativeResultIfACheckedCriIsDisabled() {
        CriEvent criEventWithCheckIfDisabledConfigured = new CriEvent(mockConfigService);
        criEventWithCheckIfDisabledConfigured.setTargetState(new State());
        criEventWithCheckIfDisabledConfigured.setCriId("aCriId");

        BasicEvent alternativeEvent = new BasicEvent(mockConfigService);
        State alternativeState = new State("THE_TARGET_STATE_FOR_THE_ALTERNATIVE_RESULT");
        JourneyResponse alternativeJourneyResponse = new JourneyResponse();
        alternativeJourneyResponse.setJourneyStepId("alternativeStepId");
        alternativeEvent.setTargetState(alternativeState);
        alternativeEvent.setResponse(alternativeJourneyResponse);

        when(mockConfigService.isEnabled("anEnabledCri")).thenReturn(true);
        when(mockConfigService.isEnabled("anotherEnabledCri")).thenReturn(true);
        when(mockConfigService.isEnabled("aDisabledCri")).thenReturn(false);
        LinkedHashMap<String, Event> checkIfDisabled = new LinkedHashMap<>();
        checkIfDisabled.put("anEnabledCri", new BasicEvent(mockConfigService));
        checkIfDisabled.put("anotherEnabledCri", new BasicEvent(mockConfigService));
        checkIfDisabled.put("aDisabledCri", alternativeEvent);
        criEventWithCheckIfDisabledConfigured.setCheckIfDisabled(checkIfDisabled);

        StateMachineResult result =
                criEventWithCheckIfDisabledConfigured.resolve(JourneyContext.emptyContext());

        assertEquals(alternativeState, result.getState());
        assertEquals(
                "alternativeStepId",
                result.getJourneyStepResponse().value(mockConfigService).get("journey"));
    }

    @Test
    void resolveShouldReturnFirstAlternativeResultIfMultipleCheckedCrisAreDisabled() {
        CriEvent criEventWithCheckIfDisabledConfigured = new CriEvent(mockConfigService);
        criEventWithCheckIfDisabledConfigured.setTargetState(new State());
        criEventWithCheckIfDisabledConfigured.setCriId("aCriId");

        BasicEvent alternativeEvent = new BasicEvent(mockConfigService);
        State alternativeState = new State("THE_TARGET_STATE_FOR_THE_ALTERNATIVE_RESULT");
        JourneyResponse alternativeJourneyResponse = new JourneyResponse();
        alternativeJourneyResponse.setJourneyStepId("alternativeStepId");
        alternativeEvent.setTargetState(alternativeState);
        alternativeEvent.setResponse(alternativeJourneyResponse);

        when(mockConfigService.isEnabled("anEnabledCri")).thenReturn(true);
        when(mockConfigService.isEnabled("aDisabledCri")).thenReturn(false);
        LinkedHashMap<String, Event> checkIfDisabled = new LinkedHashMap<>();
        checkIfDisabled.put("anEnabledCri", new BasicEvent(mockConfigService));
        checkIfDisabled.put("aDisabledCri", alternativeEvent);
        checkIfDisabled.put("anotherDisabledCri", new BasicEvent(mockConfigService));
        criEventWithCheckIfDisabledConfigured.setCheckIfDisabled(checkIfDisabled);

        StateMachineResult result =
                criEventWithCheckIfDisabledConfigured.resolve(JourneyContext.emptyContext());

        assertEquals(alternativeState, result.getState());
        assertEquals(
                "alternativeStepId",
                result.getJourneyStepResponse().value(mockConfigService).get("journey"));
    }

    @Test
    void resolveShouldReturnCriResultIfAllCheckedCrisAreEnabled() {
        State state = new State("THE_TARGET_STATE_FOR_THE_CRI_EVENT");

        CriEvent criEventWithCheckIfDisabledConfigured = new CriEvent(mockConfigService);
        criEventWithCheckIfDisabledConfigured.setTargetState(state);
        criEventWithCheckIfDisabledConfigured.setCriId("aCriId");

        when(mockConfigService.isEnabled("anEnabledCri")).thenReturn(true);
        when(mockConfigService.isEnabled("anotherEnabledCri")).thenReturn(true);
        when(mockConfigService.isEnabled("oneMoreEnabledCri")).thenReturn(true);
        LinkedHashMap<String, Event> checkIfDisabled = new LinkedHashMap<>();
        checkIfDisabled.put("anEnabledCri", new BasicEvent(mockConfigService));
        checkIfDisabled.put("anotherEnabledCri", new BasicEvent(mockConfigService));
        checkIfDisabled.put("oneMoreEnabledCri", new BasicEvent(mockConfigService));
        criEventWithCheckIfDisabledConfigured.setCheckIfDisabled(checkIfDisabled);

        StateMachineResult result =
                criEventWithCheckIfDisabledConfigured.resolve(JourneyContext.emptyContext());

        assertEquals(state, result.getState());
        assertEquals(
                "/journey/cri/build-oauth-request/aCriId",
                result.getJourneyStepResponse().value(mockConfigService).get("journey"));
    }

    @Test
    void shouldBeDeserializableFromYaml() throws Exception {
        environmentVariables.set("IS_LOCAL", "true");
        ObjectMapper om = new ObjectMapper(new YAMLFactory());
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        File file =
                new File(
                        Objects.requireNonNull(
                                        classLoader.getResource(
                                                "test/statemachine/events/criEvent.yaml"))
                                .getFile());

        CriEvent criEvent = om.readValue(file, new TypeReference<>() {});
        assertEquals("sausages", criEvent.getCriId());
        assertEquals("CRI_SAUSAGES", criEvent.getTargetState().getName());

        LinkedHashMap<String, Event> checkIfDisabledBlock = criEvent.getCheckIfDisabled();
        assertEquals(2, checkIfDisabledBlock.entrySet().size());

        BasicEvent firstAlternative =
                (BasicEvent) checkIfDisabledBlock.get("first-cri-id-to-check");
        assertEquals("sorry-page", firstAlternative.getName());
        assertEquals("SORRY_NO_SAUSAGES_PAGE", firstAlternative.getTargetState().getName());
        PageResponse firstAlternativeResponse = (PageResponse) firstAlternative.getResponse();
        assertEquals("page-sorry-no-sausages-at-the-moment", firstAlternativeResponse.getPageId());

        BasicEvent secondAlternative =
                (BasicEvent) checkIfDisabledBlock.get("second-cri-id-to-check");
        assertEquals("not-sorry-page", secondAlternative.getName());
        assertEquals("NOT_SORRY_STATE", secondAlternative.getTargetState().getName());
        PageResponse secondAlternativeResponse = (PageResponse) secondAlternative.getResponse();
        assertEquals("page-not-sorry-at-all", secondAlternativeResponse.getPageId());
    }
}
