package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;

import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;

public class CiMitUtilityService {
    private final ConfigService configService;

    public CiMitUtilityService(ConfigService configService) {
        this.configService = configService;
    }

    public boolean isBreachingCiThreshold(ContraIndicators contraIndicators) {
        return contraIndicators.getContraIndicatorScore(configService.getContraIndicatorConfigMap())
                > Integer.parseInt(configService.getSsmParameter(CI_SCORING_THRESHOLD));
    }

    public boolean isBreachingCiThresholdIfMitigated(ContraIndicator ci, ContraIndicators cis) {
        var scoreOnceMitigated =
                cis.getContraIndicatorScore(configService.getContraIndicatorConfigMap())
                        + configService
                                .getContraIndicatorConfigMap()
                                .get(ci.getCode())
                                .getCheckedScore();
        var threshold = Integer.parseInt(configService.getSsmParameter(CI_SCORING_THRESHOLD));
        return scoreOnceMitigated > threshold;
    }

    public Optional<JourneyResponse> getCiMitigationJourneyStep(ContraIndicators contraIndicators)
            throws ConfigException {
        // Try to mitigate an unmitigated ci to resolve the threshold breach
        var cimitConfig = configService.getCimitConfig();
        for (var ci : contraIndicators.getContraIndicatorsMap().values()) {
            if (isCiMitigatable(ci) && !isBreachingCiThresholdIfMitigated(ci, contraIndicators)) {
                return Optional.of(new JourneyResponse(cimitConfig.get(ci.getCode())));
            }
        }
        return Optional.empty();
    }

    private boolean isCiMitigatable(ContraIndicator ci) throws ConfigException {
        var cimitConfig = configService.getCimitConfig();
        return cimitConfig.containsKey(ci.getCode()) && !ci.isMitigated();
    }
}
