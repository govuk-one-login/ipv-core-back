package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.domain.ScopeConstants;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneyevent.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_1;

@ExtendWith(MockitoExtension.class)
public class EventResolverTest {
    @Mock private ConfigService mockConfigService;
    @Mock private CimitUtilityService mockCimitUtilityService;
    @InjectMocks private EventResolver eventResolver;

    private ClientOAuthSessionItem clientOAuthSessionItem;
    private EventResolveParameters eventResolveParameters;

    @Nested
    class BasicEventTests {
        @BeforeEach
        void setUp() {
            clientOAuthSessionItem =
                    ClientOAuthSessionItem.builder()
                            .userId("user-id")
                            .vtr(List.of(P2.name()))
                            .scope(ScopeConstants.OPENID)
                            .build();

            eventResolveParameters =
                    new EventResolveParameters(
                            Collections.emptyList(), new IpvSessionItem(), clientOAuthSessionItem);
        }

        @Test
        void resolveShouldReturnAState() throws Exception {
            var expectedResult =
                    new TransitionResult(
                            new BasicState(),
                            null,
                            null,
                            null,
                            Collections.emptyList(),
                            Collections.emptyList());
            BasicEvent basicEvent = new BasicEvent();
            basicEvent.setTargetStateObj(expectedResult.state());

            assertEquals(expectedResult, eventResolver.resolve(basicEvent, eventResolveParameters));
        }

        @Test
        void resolveShouldReturnAStateWithJourneyContexts() throws Exception {
            var expectedResult =
                    new TransitionResult(
                            new BasicState(),
                            null,
                            null,
                            null,
                            List.of("test-context-to-set"),
                            List.of("test-context-to-unset"));
            BasicEvent basicEvent = new BasicEvent();
            basicEvent.setTargetStateObj(expectedResult.state());
            basicEvent.setJourneyContextToSet("test-context-to-set");
            basicEvent.setJourneyContextToUnset("test-context-to-unset");

            assertEquals(expectedResult, eventResolver.resolve(basicEvent, eventResolveParameters));
        }

        @Test
        void resolveShouldReturnAlternativeStateIfACheckedCriIsDisabled() throws Exception {
            BasicEvent basicEventWithCheckIfDisabledConfigured = new BasicEvent();
            basicEventWithCheckIfDisabledConfigured.setTargetStateObj(new BasicState());

            BasicEvent alternativeEvent = new BasicEvent();
            BasicState alternativeTargetState = new BasicState();
            alternativeEvent.setTargetStateObj(alternativeTargetState);

            when(mockConfigService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, "anEnabledCri"))
                    .thenReturn(true);
            when(mockConfigService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, "aDisabledCri"))
                    .thenReturn(false);
            LinkedHashMap<String, Event> checkIfDisabled = new LinkedHashMap<>();
            checkIfDisabled.put("anEnabledCri", new BasicEvent());
            checkIfDisabled.put("aDisabledCri", alternativeEvent);
            basicEventWithCheckIfDisabledConfigured.setCheckIfDisabled(checkIfDisabled);

            var result =
                    eventResolver.resolve(
                            basicEventWithCheckIfDisabledConfigured, eventResolveParameters);

            assertEquals(alternativeTargetState, result.state());
        }

        @Test
        void resolveShouldReturnAlternativeStateIfACheckedFeatureFlagIsSet() throws Exception {
            BasicEvent eventWithCheckFeatureFlagConfigured = new BasicEvent();
            BasicState featureFlagTargetState = new BasicState();
            eventWithCheckFeatureFlagConfigured.setTargetStateObj(featureFlagTargetState);

            BasicEvent defaultEvent = new BasicEvent();
            defaultEvent.setTargetStateObj(new BasicState());

            LinkedHashMap<String, Event> checkFeatureFlag = new LinkedHashMap<>();
            checkFeatureFlag.put(
                    CoreFeatureFlag.UNUSED_PLACEHOLDER.getName(),
                    eventWithCheckFeatureFlagConfigured);
            defaultEvent.setCheckFeatureFlag(checkFeatureFlag);

            var result = eventResolver.resolve(defaultEvent, eventResolveParameters);

            assertEquals(featureFlagTargetState, result.state());
        }

        @Test
        void resolveShouldReturnAlternativeStateIfJourneyContextIsSetAndIgnoreFeatureFlag()
                throws Exception {
            BasicEvent eventWithCheckFeatureFlagConfigured = new BasicEvent();
            BasicState featureFlagTargetState = new BasicState();
            eventWithCheckFeatureFlagConfigured.setTargetStateObj(featureFlagTargetState);

            BasicEvent eventForCheckContext = new BasicEvent();
            BasicState checkContextTargetState =
                    new BasicState("targetEventForContext", "", null, null, null, null);
            eventForCheckContext.setTargetStateObj(checkContextTargetState);

            BasicEvent defaultEvent = new BasicEvent();
            defaultEvent.setTargetStateObj(
                    new BasicState("defaultEvent", "", null, null, null, null));

            LinkedHashMap<String, Event> checkFeatureFlag = new LinkedHashMap<>();
            checkFeatureFlag.put(
                    CoreFeatureFlag.UNUSED_PLACEHOLDER.getName(),
                    eventWithCheckFeatureFlagConfigured);
            defaultEvent.setCheckFeatureFlag(checkFeatureFlag);

            LinkedHashMap<String, Event> checkContext = new LinkedHashMap<>();
            checkContext.put("test-context", eventForCheckContext);

            defaultEvent.setCheckJourneyContext(checkContext);

            var testParams =
                    new EventResolveParameters(
                            List.of("test-context"),
                            new IpvSessionItem(),
                            ClientOAuthSessionItem.builder().scope(ScopeConstants.OPENID).build());
            var result = eventResolver.resolve(defaultEvent, testParams);

            assertEquals(checkContextTargetState, result.state());
        }

        @Nested
        class CheckMitigationConfigured {
            private IpvSessionItem ipvSessionItem;

            @BeforeEach
            void setUp() {
                ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setSecurityCheckCredential(SIGNED_CONTRA_INDICATOR_VC_1);
            }

            @Test
            void
                    resolveShouldReturnAlternativeStateIfMitigationJourneyIsFoundAndExistsInCheckMitigation()
                            throws Exception {
                // Arrange
                var basicEventWithCheckMitigationConfigured = new BasicEvent();

                var alternativeEvent = new BasicEvent();
                var alternativeTargetState = new BasicState();
                alternativeEvent.setTargetStateObj(alternativeTargetState);

                LinkedHashMap<String, Event> checkMitigation = new LinkedHashMap<>();
                checkMitigation.put("first-mitigation", alternativeEvent);

                basicEventWithCheckMitigationConfigured.setCheckMitigation(checkMitigation);

                when(mockCimitUtilityService.getMitigationEventIfBreachingOrActive(
                                any(), any(), any()))
                        .thenReturn(Optional.of("first-mitigation"));

                // Act
                var result =
                        eventResolver.resolve(
                                basicEventWithCheckMitigationConfigured,
                                new EventResolveParameters(
                                        List.of("journeyContext"),
                                        ipvSessionItem,
                                        clientOAuthSessionItem));

                // Assert
                assertEquals(alternativeTargetState, result.state());
            }

            @Test
            void
                    resolveShouldReturnTargetStateIfMitigationJourneyIsFoundButDoesNotExistInCheckMitigation()
                            throws Exception {
                // Arrange
                var basicEventWithCheckMitigationConfigured = new BasicEvent();
                var originalTargetStateObj = new BasicState();
                basicEventWithCheckMitigationConfigured.setTargetStateObj(originalTargetStateObj);

                LinkedHashMap<String, Event> checkMitigation = new LinkedHashMap<>();
                checkMitigation.put("first-mitigation", new BasicEvent());
                basicEventWithCheckMitigationConfigured.setCheckMitigation(checkMitigation);

                when(mockCimitUtilityService.getMitigationEventIfBreachingOrActive(
                                any(), any(), any()))
                        .thenReturn(Optional.of("mitigation-not-in-check-mitigation"));

                // Act
                var result =
                        eventResolver.resolve(
                                basicEventWithCheckMitigationConfigured,
                                new EventResolveParameters(
                                        List.of("journeyContext"),
                                        ipvSessionItem,
                                        clientOAuthSessionItem));

                // Assert
                assertEquals(originalTargetStateObj, result.state());
            }

            @Test
            void resolveShouldReturnTargetStateIfNoValidMitigationFoundInSecurityCheckCredential()
                    throws Exception {
                // Arrange
                var basicEventWithCheckMitigationConfigured = new BasicEvent();
                var originalTargetStateObj = new BasicState();
                basicEventWithCheckMitigationConfigured.setTargetStateObj(originalTargetStateObj);

                LinkedHashMap<String, Event> checkMitigation = new LinkedHashMap<>();

                checkMitigation.put("first-mitigation", new BasicEvent());

                basicEventWithCheckMitigationConfigured.setCheckMitigation(checkMitigation);

                when(mockCimitUtilityService.getMitigationEventIfBreachingOrActive(
                                any(), any(), any()))
                        .thenReturn(Optional.empty());

                // Act
                var result =
                        eventResolver.resolve(
                                basicEventWithCheckMitigationConfigured,
                                new EventResolveParameters(
                                        List.of("journeyContext"),
                                        ipvSessionItem,
                                        clientOAuthSessionItem));

                // Assert
                assertEquals(originalTargetStateObj, result.state());
            }

            @Test
            void
                    resolveReturnsOriginalTargetStateIfOnReverificationJourneyAndCheckMitigationIsConfigured()
                            throws Exception {
                var basicEventWithCheckMitigationConfigured = new BasicEvent();
                var originalTargetStateObj = new BasicState();
                basicEventWithCheckMitigationConfigured.setTargetStateObj(originalTargetStateObj);

                LinkedHashMap<String, Event> checkMitigation = new LinkedHashMap<>();

                checkMitigation.put("first-mitigation", new BasicEvent());

                basicEventWithCheckMitigationConfigured.setCheckMitigation(checkMitigation);

                // Act
                var result =
                        eventResolver.resolve(
                                basicEventWithCheckMitigationConfigured,
                                new EventResolveParameters(
                                        List.of("journeyContext"),
                                        ipvSessionItem,
                                        ClientOAuthSessionItem.builder()
                                                .scope(ScopeConstants.REVERIFICATION)
                                                .build()));

                // Assert
                assertEquals(originalTargetStateObj, result.state());
                verify(mockCimitUtilityService, times(0)).getContraIndicatorsFromVc(any(), any());
            }

            @Test
            void resolveShouldThrowIfIpvSessionItemDoesNotContainSecurityCheckCredential() {
                // Arrange
                var basicEventWithCheckMitigationConfigured = new BasicEvent();
                LinkedHashMap<String, Event> checkMitigation = new LinkedHashMap<>();
                checkMitigation.put("first-mitigation", new BasicEvent());
                basicEventWithCheckMitigationConfigured.setCheckMitigation(checkMitigation);

                var ipvSessionWithMissingSecurityCheckCredential = new IpvSessionItem();

                // Act/Assert
                var exception =
                        assertThrows(
                                JourneyEngineException.class,
                                () ->
                                        eventResolver.resolve(
                                                basicEventWithCheckMitigationConfigured,
                                                new EventResolveParameters(
                                                        List.of("journeyContext"),
                                                        ipvSessionWithMissingSecurityCheckCredential,
                                                        clientOAuthSessionItem)));

                assertEquals(
                        "Missing security check credential", exception.getCause().getMessage());
            }
        }
    }

    @Nested
    class ExitNestedJourneyEventTest {
        @BeforeEach
        void setUp() {
            clientOAuthSessionItem = new ClientOAuthSessionItem();
            eventResolveParameters =
                    new EventResolveParameters(
                            List.of("journeyContext"),
                            new IpvSessionItem(),
                            clientOAuthSessionItem);
        }

        @Test
        void resolveShouldResolveEventFromNestedJourneyExitEvents() throws Exception {
            var expectedResult = new BasicState();
            expectedResult.setName("target-state");

            BasicEvent nestedJourneyExitEvent = new BasicEvent();
            nestedJourneyExitEvent.setTargetStateObj(expectedResult);

            ExitNestedJourneyEvent exitNestedJourneyEvent = new ExitNestedJourneyEvent();
            exitNestedJourneyEvent.setExitEventToEmit("exiting");
            exitNestedJourneyEvent.setNestedJourneyExitEvents(
                    Map.of("exiting", nestedJourneyExitEvent));

            assertEquals(
                    expectedResult,
                    eventResolver.resolve(exitNestedJourneyEvent, eventResolveParameters).state());
        }

        @Test
        void resolveShouldThrowIfEventNotFoundInNestedJourneyExitEvents() {
            ExitNestedJourneyEvent exitNestedJourneyEvent = new ExitNestedJourneyEvent();
            exitNestedJourneyEvent.setNestedJourneyExitEvents(Map.of("exiting", new BasicEvent()));
            exitNestedJourneyEvent.setExitEventToEmit("not-found");

            assertThrows(
                    UnknownEventException.class,
                    () -> eventResolver.resolve(exitNestedJourneyEvent, eventResolveParameters));
        }
    }
}
