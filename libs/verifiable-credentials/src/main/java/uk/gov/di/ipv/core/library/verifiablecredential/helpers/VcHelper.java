package uk.gov.di.ipv.core.library.verifiablecredential.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45IdentityCheckValidator;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.PersonWithDocuments;
import uk.gov.di.model.PersonWithIdentity;
import uk.gov.di.model.RiskAssessmentCredential;

import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CHECK_EXPIRY_PERIOD_HOURS;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;

public class VcHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final List<String> DL_UK_ISSUER_LIST = Arrays.asList("DVLA", "DVA");
    private static final String UK_ICAO_ISSUER_CODE = "GBR";
    private static ConfigService configService;
    private static final int ONLY = 0;

    private VcHelper() {}

    public static void setConfigService(ConfigService configService) {
        VcHelper.configService = configService;
    }

    public static boolean isSuccessfulVc(VerifiableCredential vc) {
        if (vc.getCredential() instanceof IdentityCheckCredential identityCheckCredential) {
            var evidence = identityCheckCredential.getEvidence();
            if (isNullOrEmpty(evidence)) {
                LOGGER.warn(
                        "Unexpected missing evidence on VC from issuer: {}",
                        vc.getClaimsSet().getIssuer());
                return false;
            }
            return evidence.stream()
                    .anyMatch(
                            check -> Gpg45IdentityCheckValidator.isSuccessful(check, vc.getCri()));
        }
        return true;
    }

    public static List<VerifiableCredential> filterVCBasedOnProfileType(
            List<VerifiableCredential> vcs, ProfileType profileType) {
        if (profileType.equals(ProfileType.GPG45)) {
            return vcs.stream().filter(vc -> !vc.getCri().isOperationalCri()).toList();
        } else {
            return vcs.stream().filter(vc -> vc.getCri().isOperationalCri()).toList();
        }
    }

    public static List<String> extractTxnIdsFromCredentials(List<VerifiableCredential> vcs) {
        List<String> txnIds = new ArrayList<>();
        for (var vc : vcs) {
            if (vc.getCredential() instanceof IdentityCheckCredential identityCheckCredential) {
                var identityChecks = identityCheckCredential.getEvidence();

                if (!isNullOrEmpty(identityChecks)) {
                    txnIds.add(identityChecks.get(ONLY).getTxn());
                }
                continue;
            }

            if (vc.getCredential() instanceof RiskAssessmentCredential riskAssessmentCredential) {
                var riskAssessments = riskAssessmentCredential.getEvidence();

                if (!isNullOrEmpty(riskAssessments)) {
                    txnIds.add(riskAssessments.get(ONLY).getTxn());
                }
            }
        }
        return txnIds;
    }

    public static Integer extractAgeFromCredential(VerifiableCredential vc) {
        if (vc.getCredential().getCredentialSubject() instanceof PersonWithIdentity person) {
            var birthDates = person.getBirthDate();

            return isNullOrEmpty(birthDates) ? null : getAge(birthDates.get(ONLY).getValue());
        }
        return null;
    }

    public static Boolean checkIfDocUKIssuedForCredential(VerifiableCredential vc) {
        var credentialSubject = vc.getCredential().getCredentialSubject();

        if (credentialSubject instanceof PersonWithDocuments person) {
            var passport = person.getPassport();
            if (!isNullOrEmpty(passport)) {
                var icaoIssuerCode = passport.get(ONLY).getIcaoIssuerCode();
                if (icaoIssuerCode != null) {
                    return UK_ICAO_ISSUER_CODE.equals(icaoIssuerCode);
                }
            }

            var residencePermit = person.getResidencePermit();
            if (!isNullOrEmpty(residencePermit)) {
                var icaoIssuerCode = residencePermit.get(ONLY).getIcaoIssuerCode();
                if (icaoIssuerCode != null) {
                    return UK_ICAO_ISSUER_CODE.equals(icaoIssuerCode);
                }
            }

            // If Passport/ResidencePermit not exist then try for DL now
            var drivingPermit = person.getDrivingPermit();
            if (!isNullOrEmpty(drivingPermit)) {
                var issuer = drivingPermit.get(ONLY).getIssuedBy();
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

    public static boolean isExpiredFraudVc(VerifiableCredential vc) {
        var jwtClaimsSet = vc.getClaimsSet();
        var nbfClaim = jwtClaimsSet.getNotBeforeTime();
        var nbf = nbfClaim.toInstant();
        if (nbf == null) {
            LOGGER.error("VC does not have a nbf claim");
            return true;
        }
        var expiryPeriod =
                Integer.parseInt(configService.getSsmParameter(FRAUD_CHECK_EXPIRY_PERIOD_HOURS));
        var now = Instant.now();
        return nbf.plus(expiryPeriod, ChronoUnit.HOURS).isBefore(now);
    }
}
