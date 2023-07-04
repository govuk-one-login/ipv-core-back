package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneystep.statemachine.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@Data
public class BasicEvent implements Event {
    private static final Logger LOGGER = LogManager.getLogger();
    @JsonIgnore private ConfigService configService;
    private String name;
    private String targetState;
    private State targetStateObj;
    private LinkedHashMap<String, Event> checkIfDisabled;

    public BasicEvent() {
        this.configService = new ConfigService();
    }

    public BasicEvent(ConfigService configService) {
        this.configService = configService;
    }

    public State resolve(JourneyContext journeyContext) {
        if (checkIfDisabled != null) {
            configService.setFeatureSet(journeyContext.getFeatureSet());
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

        return targetStateObj;
    }

    @Override
    public void bootstrap(String name, Map<String, State> states) {
        this.name = name;
        if (targetState != null) {
            this.targetStateObj = states.get(targetState);
        }
        if (checkIfDisabled != null) {
            checkIfDisabled.forEach((eventName, event) -> event.bootstrap(eventName, states));
        }
    }

    @Override
    public String toString() {
        return this.name;
    }
}
