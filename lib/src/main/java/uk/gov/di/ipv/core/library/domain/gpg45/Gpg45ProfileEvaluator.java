package uk.gov.di.ipv.core.library.domain.gpg45;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.MapMessage;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.DcmawCheckMethod;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;
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

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class Gpg45ProfileEvaluator {
    public static final String JOURNEY_PYI_NO_MATCH = "/journey/pyi-no-match";
    public static final JourneyResponse JOURNEY_RESPONSE_PYI_NO_MATCH =
            new JourneyResponse(JOURNEY_PYI_NO_MATCH);
    public static final String JOURNEY_PYI_KBV_FAIL = "/journey/pyi-kbv-fail";
    public static final JourneyResponse JOURNEY_RESPONSE_PYI_KBV_FAIL =
            new JourneyResponse(JOURNEY_PYI_KBV_FAIL);
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private static final int NO_SCORE = 0;
    private static final String LOG_DESCRIPTION_FIELD = "description";
    private final CiStorageService ciStorageService;
    private final ConfigurationService configurationService;

    public Gpg45ProfileEvaluator(
            CiStorageService ciStorageService, ConfigurationService configurationService) {
        this.ciStorageService = ciStorageService;
        this.configurationService = configurationService;
    }

    public Optional<JourneyResponse> getJourneyResponseForStoredCis(
            ClientSessionDetailsDto sessionDetails, String ipAddress) throws CiRetrievalException {

        List<ContraIndicatorItem> ciItems;
        ciItems =
                ciStorageService.getCIs(
                        sessionDetails.getUserId(),
                        sessionDetails.getGovukSigninJourneyId(),
                        ipAddress);
        LOGGER.info(
                new MapMessage()
                        .with(LOG_DESCRIPTION_FIELD, "Retrieved user's CI items")
                        .with("numberOfItems", ciItems.size()));

        Set<String> ciSet =
                ciItems.stream().map(ContraIndicatorItem::getCi).collect(Collectors.toSet());

        Map<String, ContraIndicatorScore> contraIndicatorScoresMap =
                configurationService.getContraIndicatorScoresMap();

        int ciScore = 0;
        for (String ci : ciSet) {
            ContraIndicatorScore scoresConfig = contraIndicatorScoresMap.get(ci);
            ciScore += scoresConfig.getDetectedScore();
        }
        LOGGER.info(
                new MapMessage()
                        .with(LOG_DESCRIPTION_FIELD, "Calculated user's CI score")
                        .with("score", ciScore));

        int ciScoreThreshold =
                Integer.parseInt(configurationService.getSsmParameter(CI_SCORING_THRESHOLD));
        if (ciScore > ciScoreThreshold) {
            Collections.sort(ciItems);
            String lastCiIssuer = ciItems.get(ciItems.size() - 1).getIss();
            String kbvIssuer =
                    configurationService
                            .getCredentialIssuer(configurationService.getSsmParameter(KBV_CRI_ID))
                            .getAudienceForClients();

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
                                        new MapMessage()
                                                .with(
                                                        LOG_DESCRIPTION_FIELD,
                                                        "GPG45 profile has been met")
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

    public List<SignedJWT> parseCredentials(List<String> credentials) throws ParseException {
        List<SignedJWT> parsedCredentials = new ArrayList<>();
        for (String credential : credentials) {
            parsedCredentials.add(SignedJWT.parse(credential));
        }

        return parsedCredentials;
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
                        CredentialEvidenceItem.EvidenceType.DCMAW, new ArrayList<>());

        for (SignedJWT signedJWT : credentials) {
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

        int dcmawVerificationScore;
        List<DcmawCheckMethod> checkDetails = dcmawEvidenceItem.getCheckDetails();
        if (checkDetails != null) {
            dcmawVerificationScore = getDcmawVerificationScoreValue(checkDetails);
        } else {
            dcmawVerificationScore = 0;
        }

        gpg45CredentialItems.add(
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                        dcmawVerificationScore,
                        Collections.emptyList()));

        return gpg45CredentialItems;
    }

    private Integer extractMaxScoreFromEvidenceMap(
            Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap,
            CredentialEvidenceItem.EvidenceType evidenceType) {
        return evidenceMap.get(evidenceType).stream()
                .max(evidenceType.getComparator())
                .map(evidenceType.getScoreGetter())
                .orElse(NO_SCORE);
    }

    private int getDcmawVerificationScoreValue(List<DcmawCheckMethod> checkMethods) {
        Optional<DcmawCheckMethod> checkMethodWithVerificationScore =
                checkMethods.stream()
                        .filter(
                                dcmawCheckMethod ->
                                        dcmawCheckMethod.getBiometricVerificationProcessLevel()
                                                != null)
                        .findFirst();

        if (checkMethodWithVerificationScore.isPresent()) {
            return checkMethodWithVerificationScore.get().getBiometricVerificationProcessLevel();
        }
        return 0;
    }
}
