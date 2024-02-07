package uk.gov.di.ipv.core.library.verifiablecredential.helpers;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.enums.Vot;
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
import java.time.LocalDate;
import java.time.Period;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.domain.CriConstants.NON_EVIDENCE_CRI_TYPES;
import static uk.gov.di.ipv.core.library.domain.CriConstants.OPERATIONAL_CRIS;
import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_ATTR_VALUE_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_BIRTH_DATE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_DRIVING_LICENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_DRIVING_LICENCE_ISSUED_BY;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_TXN;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_PASSPORT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_PASSPORT_ICAO_CODE;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;

public class VcHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private static final List<String> DL_UK_ISSUER_LIST = Arrays.asList("DVLA", "DVA");
    public static final String UK_PASSPORT_ICAO_CODE = "GBR";
    private static ConfigService configService;
    private static final int ONLY = 0;

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

    public static List<VcStoreItem> filterVCBasedOnProfileType(
            List<VcStoreItem> vcStoreItems, ProfileType profileType) {
        if (profileType.equals(ProfileType.GPG45)) {
            return vcStoreItems.stream()
                    .filter(vcItem -> !OPERATIONAL_CRIS.contains(vcItem.getCredentialIssuer()))
                    .toList();
        } else {
            return vcStoreItems.stream()
                    .filter(
                            vcItem ->
                                    (OPERATIONAL_CRIS.contains(vcItem.getCredentialIssuer())
                                            || vcItem.getCredentialIssuer().equals(TICF_CRI)))
                    .toList();
        }
    }

    public static List<String> extractTxnIdsFromCredentials(List<SignedJWT> credentials)
            throws ParseException {
        List<String> txnIds = new ArrayList<>();
        for (SignedJWT credential : credentials) {
            var jwtClaimsSet = credential.getJWTClaimsSet();
            var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
            var evidences = (JSONArray) vc.get(VC_EVIDENCE);
            if (evidences != null) { // not all VCs have an evidence block
                var evidence = (JSONObject) evidences.get(ONLY);
                txnIds.add(evidence.getAsString(VC_EVIDENCE_TXN));
            }
        }
        return txnIds;
    }

    public static Integer extractAgeFromCredential(SignedJWT credential) throws ParseException {
        Integer age = null;
        var jwtClaimsSet = credential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var credentialSubject = (JSONObject) vc.get(VC_CREDENTIAL_SUBJECT);
        if (credentialSubject != null) {
            var birthDateArr = (JSONArray) credentialSubject.get(VC_BIRTH_DATE);
            if (birthDateArr != null) {
                var dobObj = (JSONObject) birthDateArr.get(ONLY);
                age = getAge(dobObj.getAsString(VC_ATTR_VALUE_NAME));
            }
        }
        return age;
    }

    public static Boolean checkIfDocUKIssuedForCredential(SignedJWT credential)
            throws ParseException {
        Boolean isUKIssued = null;
        boolean checkingForDL = false;
        var jwtClaimsSet = credential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var credentialSubject = (JSONObject) vc.get(VC_CREDENTIAL_SUBJECT);
        if (credentialSubject != null) {
            String docFieldAttrName = VC_PASSPORT_ICAO_CODE;
            var docFieldArr = (JSONArray) credentialSubject.get(VC_PASSPORT);
            if (docFieldArr == null) {
                // If Passport not exist then try for DL now
                docFieldArr = (JSONArray) credentialSubject.get(VC_DRIVING_LICENCE);
                docFieldAttrName = VC_DRIVING_LICENCE_ISSUED_BY;
                checkingForDL = true;
            }
            if (docFieldArr != null) {
                var docField = (JSONObject) docFieldArr.get(ONLY);
                var docFieldAttr = docField.getAsString(docFieldAttrName);
                if (docFieldAttr != null) {
                    if (checkingForDL) {
                        isUKIssued = DL_UK_ISSUER_LIST.contains(docFieldAttr);
                    } else {
                        isUKIssued = docFieldAttr.equals(UK_PASSPORT_ICAO_CODE);
                    }
                }
            }
        }
        return isUKIssued;
    }

    public static boolean isOperationalProfileVc(SignedJWT credential) throws ParseException {
        var credVot = credential.getJWTClaimsSet().getStringClaim(VOT_CLAIM_NAME);
        return credVot != null
                && Vot.valueOf(credVot).getProfileType().equals(ProfileType.OPERATIONAL_HMRC);
    }

    private static Set<String> getNonEvidenceCredentialIssuers() {
        return NON_EVIDENCE_CRI_TYPES.stream()
                .map(credentialIssuer -> configService.getComponentId(credentialIssuer))
                .collect(Collectors.toSet());
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

    private static Integer getAge(String dobValue) {
        try {
            LocalDate dob = LocalDate.parse(dobValue);
            LocalDate curDate = LocalDate.now();
            return Period.between(dob, curDate).getYears();
        } catch (Exception ex) {
            LOGGER.info("Failed to parse dob value for the vc.");
            return null;
        }
    }
}
