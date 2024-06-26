package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.MitigationRoute;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;

import java.util.List;
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
        return scoreOnceMitigated
                > Integer.parseInt(configService.getSsmParameter(CI_SCORING_THRESHOLD));
    }

    public Optional<JourneyResponse> getCiMitigationJourneyResponse(
            ContraIndicators contraIndicators) throws ConfigException {
        // Try to mitigate an unmitigated ci to resolve the threshold breach
        var cimitConfig = configService.getCimitConfig();
        for (var ci : contraIndicators.getUsersContraIndicators()) {
            if (isCiMitigatable(ci) && !isBreachingCiThresholdIfMitigated(ci, contraIndicators)) {
                // Prevent new mitigation journey if there is already a mitigated CI that fixes the
                // breach
                if (hasMitigatedContraIndicator(contraIndicators).isPresent()) {
                    return Optional.empty();
                }
                return getMitigationJourneyResponse(
                        cimitConfig.get(ci.getCode()), ci.getDocument());
            }
        }
        return Optional.empty();
    }

    public Optional<JourneyResponse> getMitigatedCiJourneyResponse(ContraIndicator ci)
            throws ConfigException {
        var cimitConfig = configService.getCimitConfig();
        if (cimitConfig.containsKey(ci.getCode()) && ci.isMitigated()) {
            return getMitigationJourneyResponse(cimitConfig.get(ci.getCode()), ci.getDocument());
        }
        return Optional.empty();
    }

    public Optional<ContraIndicator> hasMitigatedContraIndicator(
            ContraIndicators contraIndicators) {
        return contraIndicators.getUsersContraIndicators().stream()
                .filter(ContraIndicator::isMitigated)
                .findFirst();
    }

    private Optional<JourneyResponse> getMitigationJourneyResponse(
            List<MitigationRoute> mitigationRoute, String document) {
        String documentType = document != null ? document.split("/")[0] : null;
        return mitigationRoute.stream()
                .filter(mr -> (mr.document() == null || mr.document().equals(documentType)))
                .findFirst()
                .map(MitigationRoute::event)
                .map(JourneyResponse::new);
    }

    private boolean isCiMitigatable(ContraIndicator ci) throws ConfigException {
        var cimitConfig = configService.getCimitConfig();
        return cimitConfig.containsKey(ci.getCode()) && !ci.isMitigated();
    }
}
