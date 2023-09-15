package uk.gov.di.ipv.core.library.vchelper;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.Gpg45DcmawValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.Gpg45EvidenceValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.Gpg45F2fValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.Gpg45FraudValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.Gpg45NinoValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.Gpg45VerificationValidator;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.domain.CriConstants.NON_EVIDENCE_CRI_TYPES;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class VcHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private static ConfigService configService;

    private VcHelper() {}

    public static void setConfigService(ConfigService configService) {
        VcHelper.configService = configService;
    }

    private static Set<String> getNonEvidenceCredentialIssuers() {
        return NON_EVIDENCE_CRI_TYPES.stream()
                .map(credentialIssuer -> configService.getComponentId(credentialIssuer))
                .collect(Collectors.toSet());
    }

    public static boolean isSuccessfulVc(SignedJWT vc) throws ParseException {
        boolean shouldCheckContraIndicators = true;
        return isSuccessfulVc(vc, getNonEvidenceCredentialIssuers(), shouldCheckContraIndicators);
    }

    public static boolean isSuccessfulVc(SignedJWT vc, Set<String> excludedCredentialIssuers)
            throws ParseException {
        boolean shouldCheckContraIndicators = true;
        return isSuccessfulVc(vc, excludedCredentialIssuers, shouldCheckContraIndicators);
    }

    public static boolean isSuccessfulVcIgnoringCi(SignedJWT vc) throws ParseException {
        boolean shouldCheckContraIndicators = false;
        return isSuccessfulVc(vc, getNonEvidenceCredentialIssuers(), shouldCheckContraIndicators);
    }

    public static boolean isSuccessfulVcIgnoringCi(
            SignedJWT vc, Set<String> excludedCredentialIssuers) throws ParseException {
        boolean shouldCheckContraIndicators = false;
        return isSuccessfulVc(vc, excludedCredentialIssuers, shouldCheckContraIndicators);
    }

    private static boolean isSuccessfulVc(
            SignedJWT vc,
            Set<String> excludedCredentialIssuers,
            boolean shouldCheckContraIndicators)
            throws ParseException {
        JSONObject vcClaim = (JSONObject) vc.getJWTClaimsSet().getClaim(VC_CLAIM);
        JSONArray evidenceArray = (JSONArray) vcClaim.get(VC_EVIDENCE);
        if (evidenceArray == null) {
            String vcIssuer = vc.getJWTClaimsSet().getIssuer();
            if (excludedCredentialIssuers.contains(vcIssuer)) {
                return true;
            }
            LOGGER.warn("Unexpected missing evidence on VC from issuer: {}", vcIssuer);
            return false;
        }

        List<CredentialEvidenceItem> credentialEvidenceList =
                gson.fromJson(
                        evidenceArray.toJSONString(),
                        new TypeToken<List<CredentialEvidenceItem>>() {}.getType());

        return isValidEvidence(credentialEvidenceList, shouldCheckContraIndicators);
    }

    private static boolean isValidEvidence(
            List<CredentialEvidenceItem> credentialEvidenceList,
            boolean shouldCheckContraIndicators) {
        try {
            for (CredentialEvidenceItem item : credentialEvidenceList) {
                if (shouldCheckContraIndicators && item.hasContraIndicators()) {
                    return false;
                }
                CredentialEvidenceItem.EvidenceType evidenceType = item.getType();

                switch (evidenceType) {
                    case EVIDENCE -> {
                        return Gpg45EvidenceValidator.isSuccessful(item);
                    }
                    case IDENTITY_FRAUD, FRAUD_WITH_ACTIVITY -> {
                        return Gpg45FraudValidator.isSuccessful(item);
                    }
                    case VERIFICATION -> {
                        return Gpg45VerificationValidator.isSuccessful(item);
                    }
                    case DCMAW -> {
                        return Gpg45DcmawValidator.isSuccessful(item);
                    }
                    case F2F -> {
                        return Gpg45F2fValidator.isSuccessful(item);
                    }
                    case NINO -> {
                        return Gpg45NinoValidator.isSuccessful(item);
                    }
                    default -> LOGGER.info("Unexpected evidence type: {}", evidenceType);
                }
            }
            return false;
        } catch (UnknownEvidenceTypeException e) {
            return false;
        }
    }
}
