package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.MitigationRoute;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.MitigationRouteConfigNotFoundException;

import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.ALTERNATE_DOC_MITIGATION_ENABLED;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ALTERNATE_DOC_PATH;

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

    public Optional<JourneyResponse> getCiMitigationJourneyStep(ContraIndicators contraIndicators)
            throws ConfigException, MitigationRouteConfigNotFoundException {
        // Try to mitigate an unmitigated ci to resolve the threshold breach
        var cimitConfig = configService.getCimitConfig();
        for (var ci : contraIndicators.getContraIndicatorsMap().values()) {
            if (isCiMitigatable(ci) && !isBreachingCiThresholdIfMitigated(ci, contraIndicators)) {
                // Prevent new mitigation journey if there is already a mitigated CI
                if (hasMitigatedContraIndicator(contraIndicators).isPresent()) {
                    return Optional.empty();
                }
                String journeyEvent =
                        getMitigationRoute(cimitConfig.get(ci.getCode()), ci.getDocument()).event();
                if (journeyEvent.startsWith(JOURNEY_ALTERNATE_DOC_PATH)
                        && !configService.enabled(ALTERNATE_DOC_MITIGATION_ENABLED)) {
                    return Optional.empty();
                }
                return Optional.of(new JourneyResponse(journeyEvent));
            }
        }
        return Optional.empty();
    }

    private MitigationRoute getMitigationRoute(
            List<MitigationRoute> mitigationRoute, String document)
            throws MitigationRouteConfigNotFoundException {
        String documentType = document != null ? document.split("/")[0] : null;
        return mitigationRoute.stream()
                .filter(mr -> (mr.document() == null || mr.document().equals(documentType)))
                .findFirst()
                .orElseThrow(
                        () ->
                                new MitigationRouteConfigNotFoundException(
                                        "No mitigation journey route event found."));
    }

    public Optional<JourneyResponse> getMitigatedCiJourneyStep(ContraIndicator ci)
            throws ConfigException, MitigationRouteConfigNotFoundException {
        var cimitConfig = configService.getCimitConfig();
        if (isCiMitigatable(ci)) {
            return Optional.of(
                    new JourneyResponse(
                            getMitigationRoute(cimitConfig.get(ci.getCode()), ci.getDocument())
                                    .event()));
        }
        return Optional.empty();
    }

    private boolean isCiMitigatable(ContraIndicator ci) throws ConfigException {
        var cimitConfig = configService.getCimitConfig();
        return cimitConfig.containsKey(ci.getCode()) && !ci.isMitigated();
    }

    public Optional<ContraIndicator> hasMitigatedContraIndicator(
            ContraIndicators contraIndicators) {
        return contraIndicators.getContraIndicatorsMap().values().stream()
                .filter(ContraIndicator::isMitigated)
                .findFirst();
    }
}
