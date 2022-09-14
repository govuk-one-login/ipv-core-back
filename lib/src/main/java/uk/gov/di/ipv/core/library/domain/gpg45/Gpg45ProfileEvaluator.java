package uk.gov.di.ipv.core.library.domain.gpg45;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class Gpg45ProfileEvaluator {

    private static final Gson gson = new Gson();
    private static final int NO_SCORE = 0;
    public static final String JOURNEY_PYI_NO_MATCH = "/journey/pyi-no-match";
    public static final String JOURNEY_PYI_KBV_FAIL = "/journey/pyi-kbv-fail";

    public boolean credentialsSatisfyProfile(
            Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap,
            Gpg45Profile profile)
            throws UnknownEvidenceTypeException {
        return profile.isSatisfiedBy(buildScore(evidenceMap));
    }

    public Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>>
            parseGpg45ScoresFromCredentials(List<String> credentials)
                    throws ParseException, UnknownEvidenceTypeException {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.VERIFICATION, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.DCMAW, new ArrayList<>());

        for (String credential : credentials) {
            SignedJWT signedJWT = SignedJWT.parse(credential);
            JSONObject vcClaim = (JSONObject) signedJWT.getJWTClaimsSet().getClaim(VC_CLAIM);
            JSONArray evidenceArray = (JSONArray) vcClaim.get(VC_EVIDENCE);
            if (evidenceArray == null) {
                continue;
            }

            List<CredentialEvidenceItem> credentialEvidenceList =
                    gson.fromJson(
                            evidenceArray.toJSONString(),
                            new TypeToken<List<CredentialEvidenceItem>>() {}.getType());
            for (CredentialEvidenceItem evidenceItem : credentialEvidenceList) {
                evidenceItem.setCredentialIss(signedJWT.getJWTClaimsSet().getIssuer());
                evidenceMap.get(evidenceItem.getType()).add(evidenceItem);
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
                        dcmawEvidenceItem.getValidityScore(),
                        dcmawEvidenceItem.getCi()));

        gpg45CredentialItems.add(
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY,
                        dcmawEvidenceItem.getActivityHistoryScore(),
                        Collections.emptyList()));

        int dcmawVerificationScore = dcmawEvidenceItem.getCheckDetails() == null ? 0 : 2;
        gpg45CredentialItems.add(
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                        dcmawVerificationScore,
                        Collections.emptyList()));

        return gpg45CredentialItems;
    }

    private Gpg45Scores buildScore(
            Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap)
            throws UnknownEvidenceTypeException {
        List<CredentialEvidenceItem> dcmawEvidenceItems =
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.DCMAW);

        for (CredentialEvidenceItem dcmawEvidenceItem : dcmawEvidenceItems) {
            List<CredentialEvidenceItem> gpg45EvidenceItems =
                    convertDcmawEvidenceToGpg45EvidenceItems(dcmawEvidenceItem);
            for (CredentialEvidenceItem gpg45EvidenceItem : gpg45EvidenceItems) {
                evidenceMap.get(gpg45EvidenceItem.getType()).add(gpg45EvidenceItem);
            }
        }

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

    public Optional<JourneyResponse> contraIndicatorsPresent(
            Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap) {
        boolean contraIndicatorFound;
        for (CredentialEvidenceItem.EvidenceType evidenceType :
                CredentialEvidenceItem.EvidenceType.values()) {
            if (evidenceType == CredentialEvidenceItem.EvidenceType.EVIDENCE
                    || evidenceType == CredentialEvidenceItem.EvidenceType.DCMAW) {
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

                if (evidenceType.equals(CredentialEvidenceItem.EvidenceType.VERIFICATION)) {
                    return Optional.of(new JourneyResponse(JOURNEY_PYI_KBV_FAIL));
                } else {
                    return Optional.of(new JourneyResponse(JOURNEY_PYI_NO_MATCH));
                }
            }
        }
        return Optional.empty();
    }
}
