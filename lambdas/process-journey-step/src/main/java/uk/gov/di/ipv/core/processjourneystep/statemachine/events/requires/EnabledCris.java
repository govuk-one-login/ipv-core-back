package uk.gov.di.ipv.core.processjourneystep.statemachine.events.requires;

import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.List;

@Data
public class EnabledCris implements ConditionalPredicate {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ConfigService configService = new ConfigService();
    private int requiredCount;
    private List<String> criIds;

    public boolean check() {
        long enabledCount = criIds.stream()
                .map(configService::isEnabled)
                .filter(b -> b)
                .count();
        LOGGER.info("'{}' enabled CRIs found. Required: {}", enabledCount, requiredCount);
        return enabledCount >= requiredCount;
    }
}
