package uk.gov.di.ipv.core.processjourneystep.statemachine.events.requiredNotMet;

import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.CriEvent;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;

import java.util.List;

@Data
public class FirstEnabled implements ConditionalRequiredNotMet {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ConfigService configService = new ConfigService();
    private List<CriEvent> criEvents;

    public StateMachineResult resolve(JourneyContext journeyContext) {
        CriEvent firstEnabledCri = criEvents.stream()
                .filter((criEvent) -> configService.isEnabled(criEvent.getCriId()))
                .findFirst()
                .orElseThrow();

        LOGGER.info("First enabled CRI found: '{}'", firstEnabledCri.getCriId());

        return firstEnabledCri.resolve(journeyContext);
    }
}
