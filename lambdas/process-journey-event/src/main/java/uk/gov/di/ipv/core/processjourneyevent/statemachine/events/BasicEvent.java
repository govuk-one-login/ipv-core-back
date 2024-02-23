package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.JourneyChangeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@Data
public class BasicEvent implements Event {
    private static final Logger LOGGER = LogManager.getLogger();
    @JsonIgnore private ConfigService configService;
    private String name;
    private String targetJourney;
    private String targetState;
    private State targetStateObj;
    private LinkedHashMap<String, Event> checkIfDisabled;
    private LinkedHashMap<String, Event> checkFeatureFlag;

    public BasicEvent() {
        this.configService = new ConfigService();
    }

    public BasicEvent(ConfigService configService) {
        this.configService = configService;
    }

    public State resolve(JourneyContext journeyContext) throws UnknownEventException {
        configService.setFeatureSet(journeyContext.getFeatureSet());
        if (checkIfDisabled != null) {
            Optional<String> firstDisabledCri =
                    checkIfDisabled.keySet().stream()
                            .filter(id -> !configService.isEnabled(id))
                            .findFirst();
            if (firstDisabledCri.isPresent()) {
                String disabledCriId = firstDisabledCri.get();
                LOGGER.info("CRI with ID '{}' is disabled. Using alternative event", disabledCriId);
                return checkIfDisabled.get(disabledCriId).resolve(journeyContext);
            }
        }
        if (checkFeatureFlag != null) {
            Optional<String> firstFeatureFlag =
                    checkFeatureFlag.keySet().stream()
                            .filter(featureFlagValue -> configService.enabled(featureFlagValue))
                            .findFirst();
            if (firstFeatureFlag.isPresent()) {
                String featureFlagValue = firstFeatureFlag.get();
                LOGGER.info("Feature flag '{}' is set. Using alternative event", featureFlagValue);
                return checkFeatureFlag.get(featureFlagValue).resolve(journeyContext);
            }
        }
        return targetStateObj;
    }

    @Override
    public void initialize(String name, Map<String, State> states) {
        this.name = name;
        if (targetJourney != null) {
            this.targetStateObj =
                    new JourneyChangeState(IpvJourneyTypes.valueOf(targetJourney), targetState);
        } else if (targetState != null) {
            this.targetStateObj = states.get(targetState);
        }
        if (checkIfDisabled != null) {
            checkIfDisabled.forEach((eventName, event) -> event.initialize(eventName, states));
        }
        if (checkFeatureFlag != null) {
            checkFeatureFlag.forEach((eventName, event) -> event.initialize(eventName, states));
        }
    }
}
