package uk.gov.di.ipv.core.library.verifiablecredential.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45DcmawValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45EvidenceValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45F2fValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45FraudValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45NinoValidator;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45VerificationValidator;
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
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final List<String> DL_UK_ISSUER_LIST = Arrays.asList("DVLA", "DVA");
    private static final String UK_ICAO_ISSUER_CODE = "GBR";
    private static final CollectionType CREDENTIAL_EVIDENCE_ITEM_LIST_TYPE =
            OBJECT_MAPPER
                    .getTypeFactory()
                    .constructCollectionType(List.class, CredentialEvidenceItem.class);
    private static ConfigService configService;
    private static final int ONLY = 0;

    private VcHelper() {}

    public static void setConfigService(ConfigService configService) {
        VcHelper.configService = configService;
    }

    public static boolean isSuccessfulVc(VerifiableCredential vc) throws CredentialParseException {
        var evidenceArray =
                OBJECT_MAPPER.valueToTree(vc.getClaimsSet().getClaim(VC_CLAIM)).path(VC_EVIDENCE);

        var excludedCredentialIssuers = getNonEvidenceCredentialIssuers();

        if (evidenceArray.isMissingNode() || evidenceArray.isEmpty()) {
            String vcIssuer = vc.getClaimsSet().getIssuer();
            if (excludedCredentialIssuers.contains(vcIssuer)) {
                return true;
            }
            LOGGER.warn("Unexpected missing evidence on VC from issuer: {}", vcIssuer);
            return false;
        }

        try {
            return isValidEvidence(
                    OBJECT_MAPPER.treeToValue(evidenceArray, CREDENTIAL_EVIDENCE_ITEM_LIST_TYPE));
        } catch (JsonProcessingException e) {
            throw new CredentialParseException("Unable to create credential evidence list", e);
        }
    }

    public static List<VerifiableCredential> filterVCBasedOnProfileType(
            List<VerifiableCredential> vcs, ProfileType profileType) {
        if (profileType.equals(ProfileType.GPG45)) {
            return vcs.stream().filter(vc -> !OPERATIONAL_CRIS.contains(vc.getCriId())).toList();
        } else {
            return vcs.stream().filter(vc -> (OPERATIONAL_CRIS.contains(vc.getCriId()))).toList();
        }
    }

    public static List<String> extractTxnIdsFromCredentials(List<VerifiableCredential> vcs) {
        List<String> txnIds = new ArrayList<>();
        for (var vc : vcs) {
            var evidenceArray =
                    OBJECT_MAPPER
                            .valueToTree(vc.getClaimsSet().getClaim(VC_CLAIM))
                            .path(VC_EVIDENCE);
            if (evidenceArray.isArray()
                    && !evidenceArray.isEmpty()) { // not all VCs have an evidence block
                txnIds.add(evidenceArray.get(ONLY).path(VC_EVIDENCE_TXN).asText());
            }
        }
        return txnIds;
    }

    public static Integer extractAgeFromCredential(VerifiableCredential vc) {
        var birthDateArr =
                OBJECT_MAPPER
                        .valueToTree(vc.getClaimsSet().getClaim(VC_CLAIM))
                        .path(VC_CREDENTIAL_SUBJECT)
                        .path(VC_BIRTH_DATE);
        if (birthDateArr.isMissingNode() || birthDateArr.isEmpty()) {
            return null;
        }
        return getAge(birthDateArr.get(ONLY).path(VC_ATTR_VALUE_NAME).asText());
    }

    public static Boolean checkIfDocUKIssuedForCredential(VerifiableCredential vc) {
        var credentialSubject =
                OBJECT_MAPPER
                        .valueToTree(vc.getClaimsSet().getClaim(VC_CLAIM))
                        .path(VC_CREDENTIAL_SUBJECT);
        if (!credentialSubject.isMissingNode()) {
            var passportOrResPermitField =
                    credentialSubject.hasNonNull(VC_PASSPORT)
                            ? credentialSubject.path(VC_PASSPORT)
                            : credentialSubject.path(VC_RESIDENCE_PERMIT);
            if (passportOrResPermitField.isArray()) {
                var icaoCode = passportOrResPermitField.path(ONLY).path(VC_ICAO_ISSUER_CODE);
                if (!icaoCode.isMissingNode()) {
                    return UK_ICAO_ISSUER_CODE.equals(icaoCode.asText());
                }
            }
            // If Passport/ResidencePermit not exist then try for DL now
            var issuer =
                    credentialSubject
                            .path(VC_DRIVING_PERMIT)
                            .path(ONLY)
                            .path(VC_DRIVING_LICENCE_ISSUED_BY);
            if (!issuer.isMissingNode()) {
                return DL_UK_ISSUER_LIST.contains(issuer.asText());
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

    public static Vot getVcVot(VerifiableCredential vc) throws UnrecognisedVotException {
        try {
            String vot = vc.getClaimsSet().getStringClaim(VOT_CLAIM_NAME);
            return vot == null ? null : Vot.valueOf(vot);
        } catch (ParseException | IllegalArgumentException e) {
            throw new UnrecognisedVotException("Invalid VOT found for this VC");
        }
    }
}
