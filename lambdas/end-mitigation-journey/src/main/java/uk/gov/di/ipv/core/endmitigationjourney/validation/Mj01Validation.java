package uk.gov.di.ipv.core.endmitigationjourney.validation;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class Mj01Validation {

    private static final Gson gson = new Gson();
    private static final Logger LOGGER = LogManager.getLogger();

    private Mj01Validation() {}

    public static Optional<List<String>> validateJourney(
            List<String> credentials,
            ContraIndicatorItem contraIndicatorItem,
            ConfigurationService configurationService) {
        String fraudCriId =
                configurationService.getSsmParameter(ConfigurationVariable.FRAUD_CRI_ID);
        CredentialIssuerConfig fraudCriConfig =
                configurationService.getCredentialIssuer(fraudCriId);

        List<String> mitigatingVcList = new ArrayList<>();

        credentials.forEach(
                credential -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(credential);

                        if (signedJWT
                                .getJWTClaimsSet()
                                .getIssuer()
                                .equals(fraudCriConfig.getAudienceForClients())) {
                            boolean isAfterCiIssueDate =
                                    signedJWT
                                            .getJWTClaimsSet()
                                            .getNotBeforeTime()
                                            .toInstant()
                                            .isAfter(
                                                    Instant.parse(
                                                            contraIndicatorItem.getIssuedAt()));

                            if (isAfterCiIssueDate) {
                                boolean containsCi =
                                        doesVcContainCi(contraIndicatorItem.getCi(), signedJWT);

                                if (!containsCi) {
                                    mitigatingVcList.add(credential);
                                }
                            }
                        }
                    } catch (ParseException e) {
                        LOGGER.warn("Failed to parse VC");
                    }
                });

        return mitigatingVcList.isEmpty() ? Optional.empty() : Optional.of(mitigatingVcList);
    }

    private static boolean doesVcContainCi(String ci, SignedJWT signedJWT) throws ParseException {
        JSONObject vcClaim = (JSONObject) signedJWT.getJWTClaimsSet().getClaim(VC_CLAIM);
        JSONArray evidenceArray = (JSONArray) vcClaim.get(VC_EVIDENCE);

        List<CredentialEvidenceItem> credentialEvidenceList =
                gson.fromJson(
                        evidenceArray.toJSONString(),
                        new TypeToken<List<CredentialEvidenceItem>>() {}.getType());

        if (credentialEvidenceList != null) {
            Optional<CredentialEvidenceItem> matchingCi =
                    credentialEvidenceList.stream()
                            .filter(
                                    vcEvidence -> {
                                        if (vcEvidence.getCi() != null) {
                                            return vcEvidence.getCi().contains(ci);
                                        }
                                        return false;
                                    })
                            .findAny();

            return matchingCi.isPresent();
        }
        return false;
    }
}
