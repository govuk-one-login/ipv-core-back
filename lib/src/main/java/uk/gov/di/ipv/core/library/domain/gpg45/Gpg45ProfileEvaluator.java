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
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class Gpg45ProfileEvaluator {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private static final int NO_SCORE = 0;
    public static final String JOURNEY_PYI_NO_MATCH = "/journey/pyi-no-match";
    public static final JourneyResponse JOURNEY_RESPONSE_PYI_NO_MATCH =
            new JourneyResponse(JOURNEY_PYI_NO_MATCH);
    public static final String JOURNEY_PYI_KBV_FAIL = "/journey/pyi-kbv-fail";
    public static final JourneyResponse JOURNEY_RESPONSE_PYI_KBV_FAIL =
            new JourneyResponse(JOURNEY_PYI_KBV_FAIL);
    private final CiStorageService ciStorageService;
    private final ConfigurationService configurationService;

    public Gpg45ProfileEvaluator(
            CiStorageService ciStorageService, ConfigurationService configurationService) {
        this.ciStorageService = ciStorageService;
        this.configurationService = configurationService;
    }

    public Optional<JourneyResponse> contraIndicatorsPresent(
            Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap,
            ClientSessionDetailsDto sessionDetails) {

        Optional<JourneyResponse> storedCisJourneyResponse =
                getStoredCisJourneyResponse(sessionDetails);
        Optional<JourneyResponse> vcCisJourneyResponse = getVcCisJourneyResponse(evidenceMap);

        LOGGER.info(
                new StringMapMessage(
                        Map.of(
                                "message",
                                "CI response - stored vs VC",
                                "match",
                                String.valueOf(
                                        storedCisJourneyResponse.equals(vcCisJourneyResponse)),
                                "stored",
                                storedCisJourneyResponse.isPresent()
                                        ? storedCisJourneyResponse.get().getJourney()
                                        : "not present",
                                "vc",
                                vcCisJourneyResponse.isPresent()
                                        ? vcCisJourneyResponse.get().getJourney()
                                        : "not present")));

        return vcCisJourneyResponse;
    }

    public boolean credentialsSatisfyAnyProfile(
            Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap,
            List<Gpg45Profile> profiles)
            throws UnknownEvidenceTypeException {
        Gpg45Scores gpg45Scores = buildScore(evidenceMap);
        return profiles.stream().anyMatch(profile -> profile.isSatisfiedBy(gpg45Scores));
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

    private Optional<JourneyResponse> getStoredCisJourneyResponse(
            ClientSessionDetailsDto sessionDetails) {
        List<ContraIndicatorItem> ciItems;
        try {
            ciItems =
                    ciStorageService.getCIs(
                            sessionDetails.getUserId(), sessionDetails.getGovukSigninJourneyId());
            LOGGER.info("Retrieved {} CI items", ciItems.size());

        } catch (Exception e) {
            LOGGER.info("Exception thrown when calling CI storage system", e);
            ciItems = List.of();
        }

        Set<String> onlyA01Set = Set.of("A01");
        Set<String> ciSet =
                ciItems.stream().map(ContraIndicatorItem::getCi).collect(Collectors.toSet());
        boolean foundContraIndicators = !(ciSet.isEmpty() || onlyA01Set.equals(ciSet));

        if (foundContraIndicators) {
            Collections.sort(ciItems);
            String ciIssuer = ciItems.get(ciItems.size() - 1).getIss();
            String kbvIssuer =
                    configurationService
                            .getCredentialIssuer(configurationService.getSsmParameter(KBV_CRI_ID))
                            .getAudienceForClients();

            return Optional.of(
                    ciIssuer.equals(kbvIssuer)
                            ? JOURNEY_RESPONSE_PYI_KBV_FAIL
                            : JOURNEY_RESPONSE_PYI_NO_MATCH);
        } else {
            return Optional.empty();
        }
    }

    private Optional<JourneyResponse> getVcCisJourneyResponse(
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
