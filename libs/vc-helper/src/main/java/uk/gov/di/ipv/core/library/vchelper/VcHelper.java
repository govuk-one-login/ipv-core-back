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
import uk.gov.di.ipv.core.library.domain.gpg45.validation.Gpg45FraudValidator;
import uk.gov.di.ipv.core.library.domain.gpg45.validation.Gpg45VerificationValidator;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;

import java.text.ParseException;
import java.util.List;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class VcHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();

    private VcHelper() {}

    public static boolean isSuccessfulVc(SignedJWT vc, CredentialIssuerConfig addressCriConfig)
            throws ParseException {
        boolean shouldCheckContraIndicators = true;
        return isSuccessfulVc(vc, addressCriConfig, shouldCheckContraIndicators);
    }

    public static boolean isSuccessfulVcIgnoringCi(
            SignedJWT vc, CredentialIssuerConfig addressCriConfig) throws ParseException {
        boolean shouldCheckContraIndicators = false;
        return isSuccessfulVc(vc, addressCriConfig, shouldCheckContraIndicators);
    }

    private static boolean isSuccessfulVc(
            SignedJWT vc,
            CredentialIssuerConfig addressCriConfig,
            boolean shouldCheckContraIndicators)
            throws ParseException {
        JSONObject vcClaim = (JSONObject) vc.getJWTClaimsSet().getClaim(VC_CLAIM);
        JSONArray evidenceArray = (JSONArray) vcClaim.get(VC_EVIDENCE);
        if (evidenceArray == null) {
            String vcIss = vc.getJWTClaimsSet().getIssuer();
            if (vcIss.equals(addressCriConfig.getAudienceForClients())) {
                return true;
            }
            LOGGER.warn("Unexpected missing evidence on VC from issuer: {}", vcIss);
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
                if (item.getType().equals(CredentialEvidenceItem.EvidenceType.EVIDENCE)) {
                    return Gpg45EvidenceValidator.isSuccessful(item);
                } else if (item.getType()
                        .equals(CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD)) {
                    return Gpg45FraudValidator.isSuccessful(item);
                } else if (item.getType()
                        .equals(CredentialEvidenceItem.EvidenceType.VERIFICATION)) {
                    return Gpg45VerificationValidator.isSuccessful(item);
                } else if (item.getType().equals(CredentialEvidenceItem.EvidenceType.DCMAW)) {
                    return Gpg45DcmawValidator.isSuccessful(item);
                }
            }
            return false;
        } catch (UnknownEvidenceTypeException e) {
            return false;
        }
    }
}
