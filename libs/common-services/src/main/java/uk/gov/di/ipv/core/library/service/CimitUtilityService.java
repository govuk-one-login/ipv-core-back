package uk.gov.di.ipv.core.library.service;

import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.config.domain.CiRoutingConfig;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
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
        int score = getContraIndicatorScore(contraIndicators);
        int threshold =
                configService
                        .getConfiguration()
                        .getSelf()
                        .getCiScoringThresholdByVot()
                        .getThreshold(confidenceRequested.name());
        return score > threshold;
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
                > Integer.parseInt(
                        configService
                                .getConfiguration()
                                .getSelf()
                                .getCiScoringThresholdByVot()
                                .getThreshold(vot.name())
                                .toString());
    }

    public Optional<String> getRelevantMitigationEvent(
            String securityCheckCredential, String userID, Vot confidenceRequested)
            throws CiExtractionException, CredentialParseException {
        var cis = getContraIndicatorsFromVc(securityCheckCredential, userID);
        return getRelevantMitigationEvent(cis, confidenceRequested);
    }

    // If we are currently breaching the CI threshold then return the mitigation event we should use
    // to try to mitigate the CI.
    // If we aren't currently breaching but we have mitigated a CI in the past then return the
    // mitigation event for that CI so that we route consistently down the mitigation journey.
    public Optional<String> getRelevantMitigationEvent(
            List<ContraIndicator> cis, Vot confidenceRequested) {
        if (isBreachingCiThreshold(cis, confidenceRequested)) {
            return getCiMitigationEventIfNoOtherMitigations(cis, confidenceRequested);
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

    public Optional<String> getCiMitigationEventIfNoOtherMitigations(
            List<ContraIndicator> contraIndicators, Vot confidenceRequested) {
        // This check is a simplification for the implementation of core.
        // We have historically not allowed more than one manual mitigation per identity as the
        // routing would get unmanageable.
        // Caveat: If the new CI is the same type as the old one then we won't notice the mitigation
        // as CIMIT only keeps the most recent version of a CI, so the mitigated one will be
        // overwritten and we won't see it here.
        if (hasMitigatedContraIndicator(contraIndicators).isPresent()) {
            return Optional.empty();
        }

        // Try to find an unmitigated ci that could be mitigated to resolve the threshold breach
        // Note that this seems random based on the ordering of the CIs but in practice there will
        // only be one mitigation to find.
        var cimitConfig = configService.getCimitConfig();
        for (var ci : contraIndicators) {
            if (isCiMitigatable(ci)
                    && !isBreachingCiThresholdIfMitigated(
                            ci, contraIndicators, confidenceRequested)) {
                return getMitigationEvent(cimitConfig.get(ci.getCode()), ci.getDocument());
            }
        }
        return Optional.empty();
    }

    private Optional<ContraIndicator> hasMitigatedContraIndicator(
            List<ContraIndicator> contraIndicators) {
        // If user has already mitigated CI this method will return empty string
        // This is because Core allows only one mitigation to happen per user
        return contraIndicators.stream().filter(this::isMitigated).findFirst();
    }

    private Optional<String> getMitigationEvent(List<CiRoutingConfig> routes, String document) {
        // A CI may have multiple different mitigations depending on the document type, find the one
        // that matches the supplied document
        String documentType = document != null ? document.split("/")[0] : null;
        if (routes == null) return Optional.empty();
        return routes.stream()
                .filter(r -> r.getDocument() == null || r.getDocument().equals(documentType))
                .map(CiRoutingConfig::getEvent)
                .findFirst()
                .map(event -> event.substring(event.lastIndexOf('/') + 1));
    }

    private boolean isMitigated(ContraIndicator ci) {
        return ci.getMitigation() != null && !ci.getMitigation().isEmpty();
    }

    private boolean isCiMitigatable(ContraIndicator ci) {
        var cimitConfig = configService.getCimitConfig();
        return cimitConfig.containsKey(ci.getCode()) && !isMitigated(ci);
    }

    public VerifiableCredential getParsedSecurityCheckCredential(
            String securityCheckCredential, String userId) throws CredentialParseException {
        try {
            var jwt = SignedJWT.parse(securityCheckCredential);
            return VerifiableCredential.fromValidJwt(userId, Cri.CIMIT, jwt);
        } catch (ParseException e) {
            throw new CredentialParseException("Unable to parse vc string");
        }
    }

    public List<ContraIndicator> getContraIndicatorsFromVc(String vcString, String userId)
            throws CiExtractionException, CredentialParseException {
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
