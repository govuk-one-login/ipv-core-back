package uk.gov.di.ipv.core.processjourneystep.statemachine.events;

import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneystep.statemachine.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineResult;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyResponse;

@Data
public class CriEvent implements Event {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ConfigService configService = new ConfigService();
    public static final String JOURNEY_CRI_BUILD_OAUTH_REQUEST =
            "/journey/cri/build-oauth-request/%s";

    private String name;
    private State targetState;
    private String criId;
    private Event disabled;

    @Override
    public StateMachineResult resolve(JourneyContext journeyContext) {
        boolean criEnabled = configService.isEnabled(criId);
        if (criEnabled) {
            return new StateMachineResult(
                    targetState,
                    new JourneyResponse(String.format(JOURNEY_CRI_BUILD_OAUTH_REQUEST, criId)));
        } else {
            LOGGER.info("CRI with id '{}' is disabled, using alternative journey", criId);
            return disabled.resolve(journeyContext);
        }
    }
}
