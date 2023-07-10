package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneystep.statemachine.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyStepResponse;

import java.util.LinkedHashMap;
import java.util.Optional;

@Data
public class BasicEvent implements Event {
    private static final Logger LOGGER = LogManager.getLogger();
    @JsonIgnore private ConfigService configService;
    private String name;
    private State targetState;
    private JourneyStepResponse response;
    private LinkedHashMap<String, Event> checkIfDisabled;

    public BasicEvent() {
        this.configService = new ConfigService();
    }

    public BasicEvent(ConfigService configService) {
        this.configService = configService;
    }

    public StateMachineResult resolve(JourneyContext journeyContext) {
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
        return new StateMachineResult(targetState, response);
    }
}
