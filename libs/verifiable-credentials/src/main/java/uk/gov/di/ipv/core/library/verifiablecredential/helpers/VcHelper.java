package uk.gov.di.ipv.core.library.verifiablecredential.helpers;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45DcmawValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45EvidenceValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45F2fValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45FraudValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45NinoValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45TicfValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45VerificationValidator;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.domain.CriConstants.NON_EVIDENCE_CRI_TYPES;
import static uk.gov.di.ipv.core.library.domain.CriConstants.OPERATIONAL_CRIS;
import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;
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

    public static boolean isSuccessfulVc(SignedJWT vc) throws ParseException {
        JSONObject vcClaim = (JSONObject) vc.getJWTClaimsSet().getClaim(VC_CLAIM);
        JSONArray evidenceArray = (JSONArray) vcClaim.get(VC_EVIDENCE);
        var excludedCredentialIssuers = getNonEvidenceCredentialIssuers();

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

        return isValidEvidence(credentialEvidenceList);
    }

    public static boolean isSuccessfulVcs(List<SignedJWT> vcs) throws ParseException {
        if (vcs == null) return true;

        for (SignedJWT vc : vcs) {
            if (!VcHelper.isSuccessfulVc(vc)) {
                return false;
            }
        }
        return true;
    }

    private static Set<String> getNonEvidenceCredentialIssuers() {
        return NON_EVIDENCE_CRI_TYPES.stream()
                .map(credentialIssuer -> configService.getComponentId(credentialIssuer))
                .collect(Collectors.toSet());
    }

    public static List<VcStoreItem> filterVCBasedOnProfileType(
            List<VcStoreItem> vcStoreItems, ProfileType profileType) {
        List<VcStoreItem> filteredVCs;
        if (profileType.equals(ProfileType.GPG45)) {
            filteredVCs =
                    vcStoreItems.stream()
                            .filter(
                                    vcItem ->
                                            !OPERATIONAL_CRIS.contains(
                                                    vcItem.getCredentialIssuer()))
                            .toList();
        } else {
            filteredVCs =
                    vcStoreItems.stream()
                            .filter(
                                    vcItem ->
                                            (OPERATIONAL_CRIS.contains(vcItem.getCredentialIssuer())
                                                    || vcItem.getCredentialIssuer()
                                                            .equals(TICF_CRI)))
                            .toList();
        }
        return filteredVCs;
    }

    private static boolean isValidEvidence(List<CredentialEvidenceItem> credentialEvidenceList) {
        try {
            for (CredentialEvidenceItem item : credentialEvidenceList) {
                switch (item.getEvidenceType()) {
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
                    case TICF -> {
                        return Gpg45TicfValidator.isSuccessful(item);
                    }
                    default -> LOGGER.info("Unexpected evidence type: {}", item.getEvidenceType());
                }
            }
            return false;
        } catch (UnknownEvidenceTypeException e) {
            return false;
        }
    }
}
