package uk.gov.di.ipv.core.library.gpg45;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.gpg45.domain.CheckDetail;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_GPG45_PROFILE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class Gpg45ProfileEvaluator {
    public static final List<Gpg45Profile> CURRENT_ACCEPTED_GPG45_PROFILES =
            List.of(Gpg45Profile.M1A, Gpg45Profile.M1B, Gpg45Profile.M2B);
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private static final int NO_SCORE = 0;

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
                                                .with(
                                                        LOG_GPG45_PROFILE.getFieldName(),
                                                        profile.getLabel());
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
        processFraudWithActivityItems(evidenceMap);

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
                                .toList())
                .build();
    }

    private void processFraudWithActivityItems(
            Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap) {
        for (CredentialEvidenceItem evidenceItem :
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.FRAUD_WITH_ACTIVITY)) {
            evidenceMap
                    .get(CredentialEvidenceItem.EvidenceType.ACTIVITY)
                    .add(
                            new CredentialEvidenceItem(
                                    CredentialEvidenceItem.EvidenceType.ACTIVITY,
                                    evidenceItem.getActivityHistoryScore(),
                                    Collections.emptyList()));
            evidenceMap
                    .get(CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD)
                    .add(
                            new CredentialEvidenceItem(
                                    CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                                    evidenceItem.getIdentityFraudScore(),
                                    Collections.emptyList()));
        }
    }

    private void processEvidenceItems(
            Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap,
            CredentialEvidenceItem.EvidenceType evidenceType)
            throws UnknownEvidenceTypeException {
        List<CredentialEvidenceItem> evidenceItems = evidenceMap.get(evidenceType);
        for (CredentialEvidenceItem evidenceItem : evidenceItems) {
            List<CredentialEvidenceItem> gpg45EvidenceItems =
                    convertEvidenceItemToGpg45EvidenceItems(evidenceItem);
            for (CredentialEvidenceItem gpg45EvidenceItem : gpg45EvidenceItems) {
                evidenceMap.get(gpg45EvidenceItem.getEvidenceType()).add(gpg45EvidenceItem);
            }
        }
    }

    public List<SignedJWT> parseCredentials(List<String> credentials) throws ParseException {
        List<SignedJWT> parsedCredentials = new ArrayList<>();
        for (String credential : credentials) {
            parsedCredentials.add(SignedJWT.parse(credential));
        }

        return parsedCredentials;
    }

    private boolean isRelevantEvidence(CredentialEvidenceItem evidenceItem)
            throws UnknownEvidenceTypeException {
        return (evidenceItem.getEvidenceType().equals(CredentialEvidenceItem.EvidenceType.DCMAW)
                || evidenceItem.getEvidenceType().equals(CredentialEvidenceItem.EvidenceType.F2F));
    }

    private List<CredentialEvidenceItem> convertEvidenceItemToGpg45EvidenceItems(
            CredentialEvidenceItem evidenceItem) throws UnknownEvidenceTypeException {
        if (!isRelevantEvidence(evidenceItem)) {
            return Collections.emptyList();
        }
        List<CredentialEvidenceItem> gpg45CredentialItems = new ArrayList<>();

        gpg45CredentialItems.add(
                CredentialEvidenceItem.builder()
                        .strengthScore(evidenceItem.getStrengthScore())
                        .validityScore(evidenceItem.getValidityScore())
                        .ci(evidenceItem.getCi())
                        .build());

        int verificationScore;
        if (evidenceItem.getEvidenceType().equals(CredentialEvidenceItem.EvidenceType.DCMAW)) {
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
                        CredentialEvidenceItem.EvidenceType.F2F, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.FRAUD_WITH_ACTIVITY, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.NINO, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.TICF, new ArrayList<>());

        for (SignedJWT signedJWT : credentials) {
            List<CredentialEvidenceItem> credentialEvidenceList =
                    parseCredentialEvidence(signedJWT);
            for (CredentialEvidenceItem evidenceItem : credentialEvidenceList) {
                evidenceItem.setCredentialIss(signedJWT.getJWTClaimsSet().getIssuer());
                evidenceMap.get(evidenceItem.getEvidenceType()).add(evidenceItem);
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
