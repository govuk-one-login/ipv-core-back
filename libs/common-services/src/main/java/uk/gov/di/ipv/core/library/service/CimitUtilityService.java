package uk.gov.di.ipv.core.library.service;

import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.MitigationRoute;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.model.ContraIndicator;
import uk.gov.di.model.SecurityCheckCredential;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNullElse;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;

public class CimitUtilityService {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;

    public CimitUtilityService(ConfigService configService) {
        this.configService = configService;
    }

    public int getContraIndicatorScore(List<ContraIndicator> contraIndicators)
            throws UnrecognisedCiException {
        var scores = configService.getContraIndicatorConfigMap();
        validateContraIndicators(contraIndicators, scores);
        return calculateDetectedScore(contraIndicators, scores)
                + calculateCheckedScore(contraIndicators, scores);
    }

    private void validateContraIndicators(
            List<ContraIndicator> contraIndicators,
            Map<String, ContraIndicatorConfig> contraIndicatorScores)
            throws UnrecognisedCiException {
        final Set<String> knownContraIndicators = contraIndicatorScores.keySet();
        final List<String> unknownContraIndicators =
                contraIndicators.stream()
                        .map(ContraIndicator::getCode)
                        .filter(ci -> !knownContraIndicators.contains(ci))
                        .toList();
        if (!unknownContraIndicators.isEmpty()) {
            throw new UnrecognisedCiException("Unrecognised CI code received from CIMIT");
        }
    }

    private int calculateDetectedScore(
            List<ContraIndicator> contraIndicators,
            Map<String, ContraIndicatorConfig> contraIndicatorScores) {
        return contraIndicators.stream()
                .map(ContraIndicator::getCode)
                .map(
                        contraIndicatorCode ->
                                contraIndicatorScores.get(contraIndicatorCode).getDetectedScore())
                .reduce(0, Integer::sum);
    }

    private int calculateCheckedScore(
            List<ContraIndicator> contraIndicators,
            Map<String, ContraIndicatorConfig> contraIndicatorScores) {
        return contraIndicators.stream()
                .filter(this::isMitigated)
                .map(
                        contraIndicator ->
                                contraIndicatorScores
                                        .get(contraIndicator.getCode())
                                        .getCheckedScore())
                .reduce(0, Integer::sum);
    }

    public boolean isBreachingCiThreshold(
            List<ContraIndicator> contraIndicators, Vot confidenceRequested) {
        return isScoreBreachingCiThreshold(
                getContraIndicatorScore(contraIndicators), confidenceRequested);
    }

    public boolean isBreachingCiThresholdIfMitigated(
            ContraIndicator ci, List<ContraIndicator> cis, Vot confidenceRequested) {
        var scoreOnceMitigated =
                getContraIndicatorScore(cis)
                        + configService
                                .getContraIndicatorConfigMap()
                                .get(ci.getCode())
                                .getCheckedScore();
        return isScoreBreachingCiThreshold(scoreOnceMitigated, confidenceRequested);
    }

    private boolean isScoreBreachingCiThreshold(int score, Vot vot) {
        return score
                > Integer.parseInt(configService.getParameter(CI_SCORING_THRESHOLD, vot.name()));
    }

    public Optional<String> getMitigationEventIfBreachingOrActive(
            String securityCheckCredential, String userID, Vot confidenceRequested)
            throws CiExtractionException, ConfigException {
        var cis = getContraIndicatorsFromVc(securityCheckCredential, userID);
        return getMitigationEventIfBreachingOrActive(cis, confidenceRequested);
    }

    public Optional<String> getMitigationEventIfBreachingOrActive(
            List<ContraIndicator> cis, Vot confidenceRequested) throws ConfigException {
        if (isBreachingCiThreshold(cis, confidenceRequested)) {
            return getCiMitigationEvent(cis, confidenceRequested);
        } else {
            // If the user has a mitigated CI, return the mitigation to prevent
            // them from going down routes to access CRIs they gained the CI from
            var mitigatedCi = hasMitigatedContraIndicator(cis);
            if (mitigatedCi.isPresent()) {
                var cimitConfig = configService.getCimitConfig();

                return getMitigationEvent(
                        cimitConfig.get(mitigatedCi.get().getCode()),
                        mitigatedCi.get().getDocument());
            }
        }

        return Optional.empty();
    }

    public Optional<String> getCiMitigationEvent(
            List<ContraIndicator> contraIndicators, Vot confidenceRequested)
            throws ConfigException {
        // Try to mitigate an unmitigated ci to resolve the threshold breach
        var cimitConfig = configService.getCimitConfig();
        for (var ci : contraIndicators) {
            if (isCiMitigatable(ci)
                    && !isBreachingCiThresholdIfMitigated(
                            ci, contraIndicators, confidenceRequested)) {
                // Prevent new mitigation journey if there is already a mitigated CI that fixes the
                // breach
                if (hasMitigatedContraIndicator(contraIndicators).isPresent()) {
                    return Optional.empty();
                }
                return getMitigationEvent(cimitConfig.get(ci.getCode()), ci.getDocument());
            }
        }
        return Optional.empty();
    }

    public Optional<ContraIndicator> hasMitigatedContraIndicator(
            List<ContraIndicator> contraIndicators) {
        return contraIndicators.stream().filter(this::isMitigated).findFirst();
    }

    private Optional<String> getMitigationEvent(
            List<MitigationRoute> mitigationRoute, String document) {
        String documentType = document != null ? document.split("/")[0] : null;
        return mitigationRoute.stream()
                .filter(mr -> (mr.document() == null || mr.document().equals(documentType)))
                .findFirst()
                .map(MitigationRoute::event)
                .map(event -> event.substring(event.lastIndexOf("/") + 1));
    }

    private boolean isMitigated(ContraIndicator ci) {
        return ci.getMitigation() != null && !ci.getMitigation().isEmpty();
    }

    private boolean isCiMitigatable(ContraIndicator ci) throws ConfigException {
        var cimitConfig = configService.getCimitConfig();
        return cimitConfig.containsKey(ci.getCode()) && !isMitigated(ci);
    }

    public VerifiableCredential getParsedSecurityCheckCredential(
            String securityCheckCredential, String userId) throws CiExtractionException {
        try {
            var jwt = SignedJWT.parse(securityCheckCredential);
            return VerifiableCredential.fromValidJwt(userId, Cri.CIMIT, jwt);
        } catch (ParseException e) {
            throw new CiExtractionException("Unable to parse vc string");
        } catch (CredentialParseException e) {
            throw new CiExtractionException("Unable to parse claims set of credential");
        }
    }

    public List<ContraIndicator> getContraIndicatorsFromVc(String vcString, String userId)
            throws CiExtractionException {
        var credential = getParsedSecurityCheckCredential(vcString, userId);
        return getContraIndicatorsFromVc(credential);
    }

    public List<ContraIndicator> getContraIndicatorsFromVc(VerifiableCredential vc)
            throws CiExtractionException {
        if (vc.getCredential() instanceof SecurityCheckCredential cimitCredential) {
            var evidence = cimitCredential.getEvidence();
            if (evidence == null || evidence.size() != 1) {
                String message = "Unexpected evidence count";
                LOGGER.error(
                        LogHelper.buildErrorMessage(
                                message,
                                String.format(
                                        "Expected one evidence item, got %d",
                                        evidence == null ? 0 : evidence.size())));
                throw new CiExtractionException(message);
            }

            return requireNonNullElse(
                    cimitCredential.getEvidence().get(0).getContraIndicator(), List.of());
        } else {
            String message = "Unexpected vc type";
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            message,
                            String.format(
                                    "Expected SecurityCheckCredential, got %s",
                                    vc.getCredential().getClass())));
            throw new CiExtractionException(message);
        }
    }
}
