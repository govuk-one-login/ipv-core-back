package uk.gov.di.ipv.core.library.domain.gpg45;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CheckDetail;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.domain.CriConstants.KBV_CRI;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CI_SCORE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_NO_OF_CI_ITEMS;

public class Gpg45ProfileEvaluator {
    private static final String JOURNEY_PYI_NO_MATCH = "/journey/pyi-no-match";
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_NO_MATCH =
            new JourneyResponse(JOURNEY_PYI_NO_MATCH);
    private static final String JOURNEY_PYI_KBV_FAIL = "/journey/pyi-kbv-fail";
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_KBV_FAIL =
            new JourneyResponse(JOURNEY_PYI_KBV_FAIL);
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private static final int NO_SCORE = 0;
    private final ConfigService configService;

    public Gpg45ProfileEvaluator(ConfigService configService) {
        this.configService = configService;
    }

    public Optional<JourneyResponse> getJourneyResponseForStoredCis(
            List<ContraIndicatorItem> ciItems) {
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

    public Optional<Gpg45Profile> getFirstMatchingProfile(
            Gpg45Scores gpg45Scores, List<Gpg45Profile> profiles) {
        return profiles.stream()
                .filter(
                        profile -> {
                            boolean profileMet = profile.isSatisfiedBy(gpg45Scores);
                            if (profileMet) {
                                var message =
                                        new StringMapMessage()
                                                .with(
                                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                                        "GPG45 profile has been met.")
                                                .with("gpg45Profile", profile.getLabel());
                                LOGGER.info(message);
                            }
                            return profileMet;
                        })
                .findFirst();
    }

    public Gpg45Scores buildScore(List<SignedJWT> credentials)
            throws UnknownEvidenceTypeException, ParseException {
        var evidenceMap = parseGpg45ScoresFromCredentials(credentials);
        processEvidenceItems(evidenceMap, CredentialEvidenceItem.EvidenceType.DCMAW);
        processEvidenceItems(evidenceMap, CredentialEvidenceItem.EvidenceType.F2F);

        return Gpg45Scores.builder()
                .withActivity(
                        extractMaxScoreFromEvidenceMap(
                                evidenceMap, CredentialEvidenceItem.EvidenceType.ACTIVITY))
                .withFraud(
                        extractMaxScoreFromEvidenceMap(
                                evidenceMap, CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD))
                .withVerification(
                        extractMaxScoreFromEvidenceMap(
                                evidenceMap, CredentialEvidenceItem.EvidenceType.VERIFICATION))
                .withEvidences(
                        evidenceMap.get(CredentialEvidenceItem.EvidenceType.EVIDENCE).stream()
                                .map(CredentialEvidenceItem::getEvidenceScore)
                                .collect(Collectors.toList()))
                .build();
    }

    private void processEvidenceItems(
            Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap,
            CredentialEvidenceItem.EvidenceType evidenceType)
            throws UnknownEvidenceTypeException {
        List<CredentialEvidenceItem> evidenceItems = evidenceMap.get(evidenceType);
        for (CredentialEvidenceItem evidenceItem : evidenceItems) {
            List<CredentialEvidenceItem> gpg45EvidenceItems =
                    convertEvidenceToGpg45EvidenceItem(evidenceItem, evidenceType);

            for (CredentialEvidenceItem gpg45EvidenceItem : gpg45EvidenceItems) {
                evidenceMap.get(gpg45EvidenceItem.getType()).add(gpg45EvidenceItem);
            }
        }
    }

    private List<CredentialEvidenceItem> convertEvidenceToGpg45EvidenceItem(
            CredentialEvidenceItem evidenceItem, CredentialEvidenceItem.EvidenceType evidenceType)
            throws UnknownEvidenceTypeException {
        if (isRelevantEvidence(evidenceItem)) {
            return convertEvidenceItemToGpg45EvidenceItems(evidenceItem);
        }
        return Collections.emptyList();
    }

    public List<SignedJWT> parseCredentials(List<String> credentials) throws ParseException {
        List<SignedJWT> parsedCredentials = new ArrayList<>();
        for (String credential : credentials) {
            parsedCredentials.add(SignedJWT.parse(credential));
        }

        return parsedCredentials;
    }

    public Optional<SignedJWT> getCredentialByType(
            List<SignedJWT> credentials, CredentialEvidenceItem.EvidenceType evidenceType)
            throws ParseException, UnknownEvidenceTypeException {
        for (SignedJWT signedJWT : credentials) {
            List<CredentialEvidenceItem> credentialEvidenceList =
                    parseCredentialEvidence(signedJWT);
            for (CredentialEvidenceItem evidenceItem : credentialEvidenceList) {

                if (isRelevantEvidence(evidenceItem)
                        && doesEvidenceContainEvidenceType(evidenceItem, evidenceType)) {
                    return Optional.of(signedJWT);
                }

                if (evidenceItem.getType().equals(evidenceType)) {
                    return Optional.of(signedJWT);
                }
            }
        }
        return Optional.empty();
    }

    private boolean isRelevantEvidence(CredentialEvidenceItem evidenceItem)
            throws UnknownEvidenceTypeException {
        return (evidenceItem.getType().equals(CredentialEvidenceItem.EvidenceType.DCMAW)
                || evidenceItem.getType().equals(CredentialEvidenceItem.EvidenceType.F2F));
    }

    private boolean doesEvidenceContainEvidenceType(
            CredentialEvidenceItem evidenceItem, CredentialEvidenceItem.EvidenceType evidenceType)
            throws UnknownEvidenceTypeException {
        List<CredentialEvidenceItem> evidenceItems =
                convertEvidenceItemToGpg45EvidenceItems(evidenceItem);
        for (CredentialEvidenceItem item : evidenceItems) {
            if (item.getType().equals(evidenceType)) {
                return true;
            }
        }
        return false;
    }

    private List<CredentialEvidenceItem> convertEvidenceItemToGpg45EvidenceItems(
            CredentialEvidenceItem evidenceItem) throws UnknownEvidenceTypeException {
        List<CredentialEvidenceItem> gpg45CredentialItems = new ArrayList<>();

        gpg45CredentialItems.add(
                CredentialEvidenceItem.builder()
                        .strengthScore(evidenceItem.getStrengthScore())
                        .validityScore(evidenceItem.getValidityScore())
                        .ci(evidenceItem.getCi())
                        .build());

        int verificationScore;
        if (evidenceItem.getType().equals(CredentialEvidenceItem.EvidenceType.DCMAW)) {
            if (evidenceItem.getActivityHistoryScore() != null) {
                gpg45CredentialItems.add(
                        new CredentialEvidenceItem(
                                CredentialEvidenceItem.EvidenceType.ACTIVITY,
                                evidenceItem.getActivityHistoryScore(),
                                Collections.emptyList()));
            }

            List<CheckDetail> checkDetails = evidenceItem.getCheckDetails();
            if (checkDetails != null) {
                verificationScore = getVerificationScoreValue(checkDetails);
            } else {
                verificationScore = 0;
            }
        } else {
            verificationScore = evidenceItem.getVerificationScore();
        }

        gpg45CredentialItems.add(
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                        verificationScore,
                        Collections.emptyList()));

        return gpg45CredentialItems;
    }

    private List<CredentialEvidenceItem> parseCredentialEvidence(SignedJWT signedJWT)
            throws ParseException {
        JSONObject vcClaim = (JSONObject) signedJWT.getJWTClaimsSet().getClaim(VC_CLAIM);
        JSONArray evidenceArray = (JSONArray) vcClaim.get(VC_EVIDENCE);

        if (evidenceArray == null) {
            return Collections.emptyList();
        }

        return gson.fromJson(
                evidenceArray.toJSONString(),
                new TypeToken<List<CredentialEvidenceItem>>() {}.getType());
    }

    private Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>>
            parseGpg45ScoresFromCredentials(List<SignedJWT> credentials)
                    throws ParseException, UnknownEvidenceTypeException {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.VERIFICATION, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.DCMAW, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.F2F, new ArrayList<>());

        for (SignedJWT signedJWT : credentials) {
            List<CredentialEvidenceItem> credentialEvidenceList =
                    parseCredentialEvidence(signedJWT);
            for (CredentialEvidenceItem evidenceItem : credentialEvidenceList) {
                evidenceItem.setCredentialIss(signedJWT.getJWTClaimsSet().getIssuer());
                evidenceMap.get(evidenceItem.getType()).add(evidenceItem);
            }
        }

        return evidenceMap;
    }

    private Integer extractMaxScoreFromEvidenceMap(
            Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap,
            CredentialEvidenceItem.EvidenceType evidenceType) {
        return evidenceMap.get(evidenceType).stream()
                .max(evidenceType.getComparator())
                .map(evidenceType.getScoreGetter())
                .orElse(NO_SCORE);
    }

    private int getVerificationScoreValue(List<CheckDetail> checkMethods) {
        Optional<CheckDetail> checkMethodWithVerificationScore =
                checkMethods.stream()
                        .filter(
                                checkMethod ->
                                        checkMethod.getBiometricVerificationProcessLevel() != null)
                        .findFirst();

        if (checkMethodWithVerificationScore.isPresent()) {
            return checkMethodWithVerificationScore.get().getBiometricVerificationProcessLevel();
        }
        return 0;
    }
}
