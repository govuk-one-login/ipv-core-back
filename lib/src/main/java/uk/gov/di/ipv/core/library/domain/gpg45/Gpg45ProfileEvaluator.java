package uk.gov.di.ipv.core.library.domain.gpg45;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.FraudEvidenceValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.KbvEvidenceValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.PassportEvidenceValidator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class Gpg45ProfileEvaluator {

    private static final Gson gson = new Gson();
    private static final int NO_SCORE = 0;
    public static final String JOURNEY_PYI_NO_MATCH = "/journey/pyi-no-match";
    public static final String JOURNEY_PYI_KBV_FAIL = "/journey/pyi-kbv-fail";

    public Optional<JourneyResponse> getJourneyResponseIfAnyCredsFailM1A(List<String> credentials)
            throws UnknownEvidenceTypeException, ParseException {
        var evidenceMap = parseGpg45ScoresFromCredentials(credentials);

        for (CredentialEvidenceItem.EvidenceType evidenceType :
                CredentialEvidenceItem.EvidenceType.values()) {
            Optional<JourneyResponse> failedResponse =
                    getJourneyResponseIfAnyCredentialsDoNotMeetM1A(
                            evidenceType, evidenceMap.get(evidenceType));
            if (failedResponse.isPresent()) {
                LogHelper.logInfoMessageWithFieldAndValue(
                        "Credential does not meet M1A profile",
                        LogHelper.LogField.EVIDENCE_TYPE,
                        evidenceType.name());
                return failedResponse;
            }
        }
        return Optional.empty();
    }

    public boolean credentialsSatisfyProfile(List<String> credentials, Gpg45Profile profile)
            throws ParseException, UnknownEvidenceTypeException {
        var evidenceMap = parseGpg45ScoresFromCredentials(credentials);

        return profile.isSatisfiedBy(buildScore(evidenceMap))
                && !contraIndicatorsPresent(evidenceMap);
    }

    private Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>>
            parseGpg45ScoresFromCredentials(List<String> credentials)
                    throws ParseException, UnknownEvidenceTypeException {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.VERIFICATION, new ArrayList<>());

        for (String credential : credentials) {
            JSONObject vcClaim =
                    (JSONObject) SignedJWT.parse(credential).getJWTClaimsSet().getClaim(VC_CLAIM);
            JSONArray evidenceArray = (JSONArray) vcClaim.get(VC_EVIDENCE);
            if (evidenceArray == null) {
                continue;
            }

            List<CredentialEvidenceItem> credentialEvidenceList =
                    gson.fromJson(
                            evidenceArray.toJSONString(),
                            new TypeToken<List<CredentialEvidenceItem>>() {}.getType());
            for (CredentialEvidenceItem evidenceItem : credentialEvidenceList) {
                if (evidenceItem.getCheckDetails() != null
                        || evidenceItem.getFailedCheckDetails() != null) {
                    List<CredentialEvidenceItem> dcmawEvidenceItems =
                            convertDcmawEvidenceToGpg45EvidenceItems(evidenceItem);
                    for (CredentialEvidenceItem gpg45EvidenceItem : dcmawEvidenceItems) {
                        evidenceMap.get(gpg45EvidenceItem.getType()).add(gpg45EvidenceItem);
                    }
                } else {
                    evidenceMap.get(evidenceItem.getType()).add(evidenceItem);
                }
            }
        }

        return evidenceMap;
    }

    private List<CredentialEvidenceItem> convertDcmawEvidenceToGpg45EvidenceItems(
            CredentialEvidenceItem dcmawEvidenceItem) {
        List<CredentialEvidenceItem> gpg45CredentialItems = new ArrayList<>();

        gpg45CredentialItems.add(
                new CredentialEvidenceItem(
                        dcmawEvidenceItem.getStrengthScore(),
                        dcmawEvidenceItem.getValidityScore()));

        gpg45CredentialItems.add(
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY,
                        dcmawEvidenceItem.getActivityHistoryScore()));

        int dcmawVerificationScore = dcmawEvidenceItem.getCheckDetails() == null ? 0 : 2;
        gpg45CredentialItems.add(
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.VERIFICATION, dcmawVerificationScore));

        return gpg45CredentialItems;
    }

    private Gpg45Scores buildScore(
            Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap) {
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

    private Integer extractMaxScoreFromEvidenceMap(
            Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap,
            CredentialEvidenceItem.EvidenceType evidenceType) {
        return evidenceMap.get(evidenceType).stream()
                .max(evidenceType.getComparator())
                .map(evidenceType.getScoreGetter())
                .orElse(NO_SCORE);
    }

    private boolean contraIndicatorsPresent(
            Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap) {
        boolean contraIndicatorFound;
        for (CredentialEvidenceItem.EvidenceType evidenceType :
                CredentialEvidenceItem.EvidenceType.values()) {
            if (evidenceType == CredentialEvidenceItem.EvidenceType.EVIDENCE) {
                contraIndicatorFound =
                        evidenceMap.get(evidenceType).stream()
                                .anyMatch(CredentialEvidenceItem::hasContraIndicators);
            } else {
                contraIndicatorFound =
                        evidenceMap.get(evidenceType).stream()
                                .max(evidenceType.getComparator())
                                .map(CredentialEvidenceItem::hasContraIndicators)
                                .orElse(false);
            }
            if (contraIndicatorFound) {
                LogHelper.logInfoMessageWithFieldAndValue(
                        "Contra Indicators found in credentials",
                        LogHelper.LogField.EVIDENCE_TYPE,
                        evidenceType.name());
                return true;
            }
        }
        return false;
    }

    private Optional<JourneyResponse> getJourneyResponseIfAnyCredentialsDoNotMeetM1A(
            CredentialEvidenceItem.EvidenceType evidenceType,
            List<CredentialEvidenceItem> credentialEvidenceItems)
            throws UnknownEvidenceTypeException {
        switch (evidenceType) {
            case EVIDENCE:
                return getJourneyResponse(
                        credentialEvidenceItems,
                        PassportEvidenceValidator::validate,
                        JOURNEY_PYI_NO_MATCH);
            case IDENTITY_FRAUD:
                return getJourneyResponse(
                        credentialEvidenceItems,
                        FraudEvidenceValidator::validate,
                        JOURNEY_PYI_NO_MATCH);
            case VERIFICATION:
                return getJourneyResponse(
                        credentialEvidenceItems,
                        KbvEvidenceValidator::validate,
                        JOURNEY_PYI_KBV_FAIL);
            case ACTIVITY:
                return Optional.empty();
            default:
                throw new UnknownEvidenceTypeException();
        }
    }

    private Optional<JourneyResponse> getJourneyResponse(
            List<CredentialEvidenceItem> credentialEvidenceItems,
            Predicate<CredentialEvidenceItem> validator,
            String journeyResponseValue) {
        for (CredentialEvidenceItem item : credentialEvidenceItems) {
            if (!validator.test(item)) {
                return Optional.of(new JourneyResponse(journeyResponseValue));
            }
        }
        return Optional.empty();
    }
}
