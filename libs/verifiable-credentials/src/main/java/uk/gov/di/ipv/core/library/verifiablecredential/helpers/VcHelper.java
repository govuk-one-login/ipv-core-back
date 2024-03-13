package uk.gov.di.ipv.core.library.verifiablecredential.helpers;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45DcmawValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45EvidenceValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45F2fValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45FraudValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45NinoValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45TicfValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45VerificationValidator;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;
import java.time.LocalDate;
import java.time.Period;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.domain.CriConstants.NON_EVIDENCE_CRI_TYPES;
import static uk.gov.di.ipv.core.library.domain.CriConstants.OPERATIONAL_CRIS;
import static uk.gov.di.ipv.core.library.domain.CriConstants.TICF_CRI;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_ATTR_VALUE_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_BIRTH_DATE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_DRIVING_LICENCE_ISSUED_BY;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_DRIVING_PERMIT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_TXN;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_ICAO_ISSUER_CODE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_PASSPORT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_RESIDENCE_PERMIT;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;

public class VcHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private static final List<String> DL_UK_ISSUER_LIST = Arrays.asList("DVLA", "DVA");
    public static final String UK_ICAO_ISSUER_CODE = "GBR";
    private static ConfigService configService;
    private static final int ONLY = 0;

    private VcHelper() {}

    public static void setConfigService(ConfigService configService) {
        VcHelper.configService = configService;
    }

    public static boolean isSuccessfulVc(VerifiableCredential vc) {
        JSONObject vcClaim = (JSONObject) vc.getClaimsSet().getClaim(VC_CLAIM);
        JSONArray evidenceArray = (JSONArray) vcClaim.get(VC_EVIDENCE);
        var excludedCredentialIssuers = getNonEvidenceCredentialIssuers();

        if (evidenceArray == null || evidenceArray.isEmpty()) {
            String vcIssuer = vc.getClaimsSet().getIssuer();
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

    public static List<VerifiableCredential> filterVCBasedOnProfileType(
            List<VerifiableCredential> vcs, ProfileType profileType) {
        if (profileType.equals(ProfileType.GPG45)) {
            return vcs.stream().filter(vc -> !OPERATIONAL_CRIS.contains(vc.getCriId())).toList();
        } else {
            return vcs.stream()
                    .filter(
                            vc ->
                                    (OPERATIONAL_CRIS.contains(vc.getCriId())
                                            || vc.getCriId().equals(TICF_CRI)))
                    .toList();
        }
    }

    public static List<String> extractTxnIdsFromCredentials(List<VerifiableCredential> vcs) {
        List<String> txnIds = new ArrayList<>();
        for (var vc : vcs) {
            var jwtClaimsSet = vc.getClaimsSet();
            var vcClaim = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
            var evidences = (JSONArray) vcClaim.get(VC_EVIDENCE);
            if (evidences != null) { // not all VCs have an evidence block
                var evidence = (JSONObject) evidences.get(ONLY);
                txnIds.add(evidence.getAsString(VC_EVIDENCE_TXN));
            }
        }
        return txnIds;
    }

    public static Integer extractAgeFromCredential(VerifiableCredential vc) {
        Integer age = null;
        var jwtClaimsSet = vc.getClaimsSet();
        var vcClaim = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var credentialSubject = (JSONObject) vcClaim.get(VC_CREDENTIAL_SUBJECT);
        if (credentialSubject != null && !credentialSubject.isEmpty()) {
            var birthDateArr = (JSONArray) credentialSubject.get(VC_BIRTH_DATE);
            if (birthDateArr != null && !birthDateArr.isEmpty()) {
                var dobObj = (JSONObject) birthDateArr.get(ONLY);
                age = getAge(dobObj.getAsString(VC_ATTR_VALUE_NAME));
            }
        }
        return age;
    }

    public static Boolean checkIfDocUKIssuedForCredential(VerifiableCredential vc) {
        var jwtClaimsSet = vc.getClaimsSet();
        var vcClaim = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
        var credentialSubject = (JSONObject) vcClaim.get(VC_CREDENTIAL_SUBJECT);
        if (credentialSubject != null) {
            var passportOrResPermitField = getPassportOrResPermitField(credentialSubject);
            if (passportOrResPermitField instanceof JSONArray passportOrResPermitFieldArr) {
                var icaoCode =
                        ((JSONObject) passportOrResPermitFieldArr.get(ONLY))
                                .getAsString(VC_ICAO_ISSUER_CODE);
                if (icaoCode != null) {
                    return UK_ICAO_ISSUER_CODE.equals(icaoCode);
                }
            }
            // If Passport/ResidencePermit not exist then try for DL now
            var dlField = credentialSubject.get(VC_DRIVING_PERMIT);
            if (dlField instanceof JSONArray dlFieldArr) {
                var issuer =
                        ((JSONObject) dlFieldArr.get(ONLY))
                                .getAsString(VC_DRIVING_LICENCE_ISSUED_BY);
                if (issuer != null) {
                    return DL_UK_ISSUER_LIST.contains(issuer);
                }
            }
        }
        return null; // NOSONAR
    }

    public static boolean isOperationalProfileVc(VerifiableCredential vc) throws ParseException {
        var vot = vc.getClaimsSet().getStringClaim(VOT_CLAIM_NAME);
        return vot != null
                && Vot.valueOf(vot).getProfileType().equals(ProfileType.OPERATIONAL_HMRC);
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

    private static Object getPassportOrResPermitField(JSONObject credentialSubject) {
        // If Passport not exist then try for ResidencePermit (BRP/BRC/FWP)
        Object docField = credentialSubject.get(VC_PASSPORT);
        if (Objects.isNull(docField)) {
            docField = credentialSubject.get(VC_RESIDENCE_PERMIT);
        }
        return docField;
    }

    public static Vot getVcVot(VerifiableCredential vc) throws UnrecognisedVotException {
        try {
            String vot = vc.getClaimsSet().getStringClaim(VOT_CLAIM_NAME);
            return vot == null ? null : Vot.valueOf(vot);
        } catch (ParseException | IllegalArgumentException e) {
            throw new UnrecognisedVotException("Invalid VOT found for this VC");
        }
    }
}
