package uk.gov.di.ipv.core.evaluategpg45scores.gpg45;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.evaluategpg45scores.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.evaluategpg45scores.domain.CredentialEvidenceItem.EvidenceType;
import uk.gov.di.ipv.core.evaluategpg45scores.exception.UnknownEvidenceTypeException;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class Gpg45ProfileEvaluator {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private static final int NO_SCORE = 0;

    public boolean credentialsSatisfyProfile(List<String> credentials, Gpg45Profile profile)
            throws ParseException, UnknownEvidenceTypeException {
        var evidenceMap = parseGpg45ScoresFromCredentials(credentials);
        return profile.satisfiedBy(buildScore(evidenceMap))
                && !contraIndicatorsPresent(evidenceMap);
    }

    private Map<EvidenceType, List<CredentialEvidenceItem>> parseGpg45ScoresFromCredentials(
            List<String> credentials) throws ParseException, UnknownEvidenceTypeException {
        Map<EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        EvidenceType.ACTIVITY, new ArrayList<>(),
                        EvidenceType.EVIDENCE, new ArrayList<>(),
                        EvidenceType.IDENTITY_FRAUD, new ArrayList<>(),
                        EvidenceType.VERIFICATION, new ArrayList<>());

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
                evidenceMap.get(evidenceItem.getType()).add(evidenceItem);
            }
        }

        return evidenceMap;
    }

    private Gpg45Scores buildScore(Map<EvidenceType, List<CredentialEvidenceItem>> evidenceMap) {
        return Gpg45Scores.builder()
                .withActivity(extractMaxScoreFromEvidenceMap(evidenceMap, EvidenceType.ACTIVITY))
                .withFraud(extractMaxScoreFromEvidenceMap(evidenceMap, EvidenceType.IDENTITY_FRAUD))
                .withVerification(
                        extractMaxScoreFromEvidenceMap(evidenceMap, EvidenceType.VERIFICATION))
                .withEvidences(
                        evidenceMap.get(EvidenceType.EVIDENCE).stream()
                                .map(CredentialEvidenceItem::getEvidenceScore)
                                .collect(Collectors.toList()))
                .build();
    }

    private Integer extractMaxScoreFromEvidenceMap(
            Map<EvidenceType, List<CredentialEvidenceItem>> evidenceMap,
            EvidenceType evidenceType) {
        return evidenceMap.get(evidenceType).stream()
                .max(evidenceType.getComparator())
                .map(evidenceType.getScoreGetter())
                .orElse(NO_SCORE);
    }

    private boolean contraIndicatorsPresent(
            Map<EvidenceType, List<CredentialEvidenceItem>> evidenceMap) {
        boolean contraIndicatorFound;
        for (EvidenceType evidenceType : EvidenceType.values()) {
            if (evidenceType == EvidenceType.EVIDENCE) {
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
}
