package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.utils.StringUtils;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.VotHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneyevent.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.MissingSecurityCheckCredential;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;

import java.text.ParseException;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_SECURITY_CHECK_CREDENTIAL;

public class EventResolver {
    private static final Logger LOGGER = LogManager.getLogger();
    private final CimitUtilityService cimitUtilityService;
    private final ConfigService configService;

    public EventResolver(CimitUtilityService cimitUtilityService, ConfigService configService) {
        this.cimitUtilityService = cimitUtilityService;
        this.configService = configService;
    }

    public TransitionResult resolve(Event event, EventResolveParameters parameters)
            throws JourneyEngineException, UnknownEventException {
        if (event instanceof BasicEvent basicEvent) {
            return resolveBasicEvent(basicEvent, parameters);
        } else if (event instanceof ExitNestedJourneyEvent exitNestedJourneyEvent) {
            return resolveExitNestedJourneyEvent(exitNestedJourneyEvent, parameters);
        }
        throw new JourneyEngineException("Unknown event type passed into EventResolver");
    }

    private TransitionResult resolveExitNestedJourneyEvent(
            ExitNestedJourneyEvent event, EventResolveParameters parameters)
            throws JourneyEngineException, UnknownEventException {
        var exitEventToEmit = event.getExitEventToEmit();
        Event exitEvent = event.getNestedJourneyExitEvents().get(exitEventToEmit);
        if (exitEvent == null) {
            throw new UnknownEventException(
                    "Event '%s' not found in nested journey's exit events"
                            .formatted(exitEventToEmit));
        }
        return resolve(exitEvent, parameters);
    }

    private TransitionResult resolveBasicEvent(
            BasicEvent event, EventResolveParameters resolveParameters)
            throws UnknownEventException, JourneyEngineException {
        try {
            var journeyContext = resolveParameters.journeyContext();

            if (event.getCheckIfDisabled() != null) {
                var checkIfDisabled = event.getCheckIfDisabled();
                Optional<String> firstDisabledCri =
                        checkIfDisabled.keySet().stream()
                                .filter(
                                        id ->
                                                !configService.getBooleanParameter(
                                                        CREDENTIAL_ISSUER_ENABLED, id))
                                .findFirst();
                if (firstDisabledCri.isPresent()) {
                    String disabledCriId = firstDisabledCri.get();
                    LOGGER.info(
                            "CRI with ID '{}' is disabled. Using alternative event", disabledCriId);
                    return resolve(checkIfDisabled.get(disabledCriId), resolveParameters);
                }
            }
            if (event.getCheckJourneyContext() != null && !StringUtils.isEmpty(journeyContext)) {
                var checkJourneyContext = event.getCheckJourneyContext();
                Optional<String> matchingContext =
                        checkJourneyContext.keySet().stream()
                                .filter(ctx -> ctx.equals(journeyContext))
                                .findFirst();
                if (matchingContext.isPresent()) {
                    String contextValue = matchingContext.get();
                    LOGGER.info(
                            "Matching context '{}' is set. Using alternative event", contextValue);
                    return resolve(checkJourneyContext.get(contextValue), resolveParameters);
                }
            }
            if (event.getCheckFeatureFlag() != null) {
                var checkFeatureFlag = event.getCheckFeatureFlag();
                Optional<String> firstFeatureFlag =
                        checkFeatureFlag.keySet().stream()
                                .filter(configService::enabled)
                                .findFirst();
                if (firstFeatureFlag.isPresent()) {
                    String featureFlagValue = firstFeatureFlag.get();
                    LOGGER.info(
                            "Feature flag '{}' is set. Using alternative event", featureFlagValue);
                    return resolve(checkFeatureFlag.get(featureFlagValue), resolveParameters);
                }
            }

            if (isCheckMitigationAllowed(event, resolveParameters.clientOAuthSessionItem())) {
                var checkMitigation = event.getCheckMitigation();
                var matchedMitigation = getMitigationEvent(event, resolveParameters);

                if (matchedMitigation.isPresent()) {
                    var mitigationEvent = checkMitigation.get(matchedMitigation.get());
                    LOGGER.info(
                            "Mitigation '{}' found. Using alternative event.",
                            matchedMitigation.get());
                    return resolve(mitigationEvent, resolveParameters);
                }
            }

            return new TransitionResult(
                    event.getTargetStateObj(),
                    event.getAuditEvents(),
                    event.getAuditContext(),
                    event.getTargetEntryEvent());
        } catch (MissingSecurityCheckCredential
                | CiExtractionException
                | CredentialParseException
                | ParseException
                | ConfigException e) {
            throw new JourneyEngineException("Failed to resolve event", e);
        }
    }

    private boolean isCheckMitigationAllowed(
            BasicEvent event, ClientOAuthSessionItem clientOAuthSessionItem) {
        return event.getCheckMitigation() != null && !clientOAuthSessionItem.isReverification();
    }

    private Optional<String> getMitigationEvent(
            BasicEvent event, EventResolveParameters resolveParameters)
            throws MissingSecurityCheckCredential, CiExtractionException, CredentialParseException,
                    ParseException, ConfigException {
        var ipvSessionItem = resolveParameters.ipvSessionItem();
        var clientOAuthSessionItem = resolveParameters.clientOAuthSessionItem();
        var securityCheckCredential = ipvSessionItem.getSecurityCheckCredential();

        if (StringUtils.isEmpty(securityCheckCredential)) {
            LOGGER.error(LogHelper.buildErrorMessage(MISSING_SECURITY_CHECK_CREDENTIAL));
            throw new MissingSecurityCheckCredential("Missing security check credential");
        }

        var contraIndicators =
                cimitUtilityService.getContraIndicatorsFromVc(
                        securityCheckCredential, clientOAuthSessionItem.getUserId());

        var validMitigation =
                cimitUtilityService.getMitigationEventIfBreachingOrActive(
                        contraIndicators,
                        VotHelper.getThresholdVot(ipvSessionItem, clientOAuthSessionItem));

        return (validMitigation.isPresent()
                        && event.getCheckMitigation().containsKey(validMitigation.get()))
                ? validMitigation
                : Optional.empty();
    }
}
