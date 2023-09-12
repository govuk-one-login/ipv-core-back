package uk.gov.di.ipv.core.library.domain.cimit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorMitigation;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.MitigationService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.MITIGATION_ENABLED;
import static uk.gov.di.ipv.core.library.domain.CriConstants.KBV_CRI;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CI_SCORE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_NO_OF_CI_ITEMS;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_PYI_KBV_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_PYI_NO_MATCH_PATH;

public class CimitEvaluator {
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_NO_MATCH =
            new JourneyResponse(JOURNEY_PYI_NO_MATCH_PATH);
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_KBV_FAIL =
            new JourneyResponse(JOURNEY_PYI_KBV_FAIL_PATH);
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;
    private final MitigationService mitigationService;

    public CimitEvaluator(ConfigService configService, MitigationService mitigationService) {
        this.configService = configService;
        this.mitigationService = mitigationService;
    }

    public Optional<JourneyResponse> getJourneyResponseForStoredCis(
            List<ContraIndicatorItem> ciItems) throws UnrecognisedCiException {
        List<ContraIndicatorItem> contraIndicatorItems = new ArrayList<>(ciItems);
        LOGGER.info(
                new StringMapMessage()
                        .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "Retrieved user's CI items.")
                        .with(LOG_NO_OF_CI_ITEMS.getFieldName(), ciItems.size()));

        Set<String> ciSet =
                contraIndicatorItems.stream()
                        .map(ContraIndicatorItem::getCi)
                        .collect(Collectors.toSet());

        Map<String, ContraIndicatorScore> contraIndicatorScoresMap =
                configService.getContraIndicatorScoresMap();

        int ciScore = 0;
        for (String ci : ciSet) {
            if (!contraIndicatorScoresMap.containsKey(ci)) {
                throw new UnrecognisedCiException("Unrecognised CI code received from CIMIT");
            }
            ContraIndicatorScore scoresConfig = contraIndicatorScoresMap.get(ci);
            ciScore += scoresConfig.getDetectedScore();
        }
        LOGGER.info(
                new StringMapMessage()
                        .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "Calculated user's CI score.")
                        .with(LOG_CI_SCORE.getFieldName(), ciScore));

        int ciScoreThreshold =
                Integer.parseInt(configService.getSsmParameter(CI_SCORING_THRESHOLD));
        if (ciScore > ciScoreThreshold) {
            Collections.sort(contraIndicatorItems);
            String lastCiIssuer =
                    contraIndicatorItems.get(contraIndicatorItems.size() - 1).getIss();
            String kbvIssuer = configService.getComponentId(KBV_CRI);

            return Optional.of(
                    lastCiIssuer.equals(kbvIssuer)
                            ? JOURNEY_RESPONSE_PYI_KBV_FAIL
                            : JOURNEY_RESPONSE_PYI_NO_MATCH);
        } else {
            return Optional.empty();
        }
    }

    private Optional<ContraIndicator> checkForBreachingContraIndicators(
            ContraIndicators contraIndicators) throws UnrecognisedCiException {
        LOGGER.info(
                new StringMapMessage()
                        .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "Retrieved user's CI items.")
                        .with(
                                LOG_NO_OF_CI_ITEMS.getFieldName(),
                                contraIndicators.getContraIndicatorsMap().size()));
        final int ciScore =
                contraIndicators.getContraIndicatorScore(
                        configService.getContraIndicatorScoresMap(),
                        configService.enabled(MITIGATION_ENABLED));
        LOGGER.info(
                new StringMapMessage()
                        .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "Calculated user's CI score.")
                        .with(LOG_CI_SCORE.getFieldName(), ciScore));

        if (ciScore <= Integer.parseInt(configService.getSsmParameter(CI_SCORING_THRESHOLD))) {
            return Optional.empty();
        }
        return contraIndicators.getLatestContraIndicator();
    }

    public Optional<JourneyResponse> getJourneyResponseForStoredContraIndicators(
            String userId, ContraIndicators contraIndicators, boolean separateSession)
            throws ConfigException, UnrecognisedCiException {
        final Optional<ContraIndicator> latestBreachingContraIndicator =
                checkForBreachingContraIndicators(contraIndicators);
        if (latestBreachingContraIndicator.isEmpty()) {
            return Optional.empty();
        }
        final String latestContraIndicatorCode = latestBreachingContraIndicator.get().getCode();
        Map<String, ContraIndicatorMitigation> ciMitConfig = configService.getCiMitConfig();
        if (ciMitConfig.containsKey(latestContraIndicatorCode)) {
            mitigationService.addInFlightMitigation(userId, latestContraIndicatorCode);
            final ContraIndicatorMitigation contraIndicatorMitigation =
                    ciMitConfig.get(latestContraIndicatorCode);
            return Optional.of(
                    new JourneyResponse(
                            separateSession
                                    ? contraIndicatorMitigation.getSeparateSessionStep()
                                    : contraIndicatorMitigation.getSameSessionStep()));
        }

        return Optional.of(JOURNEY_RESPONSE_PYI_NO_MATCH);
    }
}
