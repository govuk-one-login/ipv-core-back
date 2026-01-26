package uk.gov.di.ipv.core.library.verifiablecredential.helpers;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.gpg45.validators.Gpg45IdentityCheckValidator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.model.BirthDate;
import uk.gov.di.model.CheckDetails;
import uk.gov.di.model.DrivingPermitDetails;
import uk.gov.di.model.IdentityCheck;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.PassportDetails;
import uk.gov.di.model.PersonWithDocuments;
import uk.gov.di.model.PersonWithIdentity;
import uk.gov.di.model.ResidencePermitDetails;
import uk.gov.di.model.RiskAssessment;
import uk.gov.di.model.RiskAssessmentCredential;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.helpers.ListHelper.extractFromFirstElementOfList;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ISSUER;
import static uk.gov.di.model.CheckDetails.FraudCheckType.APPLICABLE_AUTHORITATIVE_SOURCE;
import static uk.gov.di.model.CheckDetails.FraudCheckType.AVAILABLE_AUTHORITATIVE_SOURCE;

public class VcHelper {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final List<String> DL_UK_ISSUER_LIST = Arrays.asList("DVLA", "DVA");
    private static final String UK_ICAO_ISSUER_CODE = "GBR";
    private static final ZoneId LONDON_TIMEZONE = ZoneId.of("Europe/London");

    private VcHelper() {}

    public static boolean isSuccessfulVc(VerifiableCredential vc) {
        if (vc.getCredential() instanceof IdentityCheckCredential identityCheckCredential) {
            var evidence = identityCheckCredential.getEvidence();
            if (isNullOrEmpty(evidence)) {
                LOGGER.warn(
                        LogHelper.buildLogMessage("Unexpected missing evidence on VC")
                                .with(
                                        LOG_CRI_ISSUER.getFieldName(),
                                        vc.getClaimsSet().getIssuer()));
                return false;
            }
            return evidence.stream()
                    .anyMatch(
                            check -> Gpg45IdentityCheckValidator.isSuccessful(check, vc.getCri()));
        }
        return true;
    }

    public static List<String> extractTxnIdsFromCredentials(List<VerifiableCredential> vcs) {
        var identityCheckTxns =
                vcs.stream()
                        .map(VerifiableCredential::getCredential)
                        .filter(IdentityCheckCredential.class::isInstance)
                        .flatMap(
                                credential ->
                                        Optional.ofNullable(
                                                ((IdentityCheckCredential) credential)
                                                        .getEvidence())
                                                .orElse(List.of())
                                                .stream())
                        .map(IdentityCheck::getTxn)
                        .toList();

        var riskAssessmentTxns =
                vcs.stream()
                        .map(VerifiableCredential::getCredential)
                        .filter(RiskAssessmentCredential.class::isInstance)
                        .flatMap(
                                credential ->
                                        Optional.ofNullable(
                                                ((RiskAssessmentCredential) credential)
                                                        .getEvidence())
                                                .orElse(List.of())
                                                .stream())
                        .map(RiskAssessment::getTxn)
                        .toList();

        return Stream.of(identityCheckTxns, riskAssessmentTxns)
                .flatMap(Collection::stream)
                .toList();
    }

    public static Integer extractAgeFromCredential(VerifiableCredential vc) {
        if (vc.getCredential().getCredentialSubject() instanceof PersonWithIdentity person) {
            var birthDate =
                    extractFromFirstElementOfList(person.getBirthDate(), BirthDate::getValue);

            return birthDate == null ? null : getAge(birthDate);
        }
        return null;
    }

    public static Boolean checkIfDocUKIssuedForCredential(VerifiableCredential vc) {
        var credentialSubject = vc.getCredential().getCredentialSubject();

        if (credentialSubject instanceof PersonWithDocuments person) {
            String icaoIssuerCode;

            icaoIssuerCode =
                    extractFromFirstElementOfList(
                            person.getPassport(), PassportDetails::getIcaoIssuerCode);
            if (icaoIssuerCode != null) {
                return UK_ICAO_ISSUER_CODE.equals(icaoIssuerCode);
            }

            icaoIssuerCode =
                    extractFromFirstElementOfList(
                            person.getResidencePermit(), ResidencePermitDetails::getIcaoIssuerCode);
            if (icaoIssuerCode != null) {
                return UK_ICAO_ISSUER_CODE.equals(icaoIssuerCode);
            }

            // If Passport/ResidencePermit not exist then try for DL now
            var issuer =
                    extractFromFirstElementOfList(
                            person.getDrivingPermit(), DrivingPermitDetails::getIssuedBy);
            if (issuer != null) {
                return DL_UK_ISSUER_LIST.contains(issuer);
            }
        }
        return null; // NOSONAR
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

    public static boolean allFraudVcsAreExpiredOrFromUnavailableSource(
            List<VerifiableCredential> vcs, ConfigService configService) {
        return vcs.stream()
                .filter(vc -> vc.getCri() == EXPERIAN_FRAUD)
                .allMatch(
                        vc ->
                                VcHelper.isExpiredFraudVc(vc, configService, Clock.systemUTC())
                                        || VcHelper.hasUnavailableFraudCheck(vc));
    }

    public static boolean allFraudVcsAreExpiredOrFromUnavailableSource(
            List<VerifiableCredential> vcs, ConfigService configService, Clock clock) {
        return vcs.stream()
                .filter(vc -> vc.getCri() == EXPERIAN_FRAUD)
                .allMatch(
                        vc ->
                                VcHelper.isExpiredFraudVc(vc, configService, clock)
                                        || VcHelper.hasUnavailableFraudCheck(vc));
    }

    public static boolean isExpiredFraudVc(
            VerifiableCredential vc, ConfigService configService, Clock clock) {
        var jwtClaimsSet = vc.getClaimsSet();
        var nbfDate = jwtClaimsSet.getNotBeforeTime();
        var nbf = nbfDate.toInstant();
        if (nbf == null) {
            LOGGER.error("VC does not have a nbf claim");
            return true;
        }

        var expiryPeriodInDays = configService.getFraudCheckExpiryPeriodDays();
        return hasExpired(nbf, expiryPeriodInDays, clock);
    }

    public static boolean isExpiredDrivingPermitVc(
            VerifiableCredential drivingPermitVc, ConfigService configService, Clock clock) {
        var validityDurationInDays = configService.getDcmawExpiredDlValidityPeriodDays();
        var nbf = drivingPermitVc.getClaimsSet().getNotBeforeTime();

        if (validityDurationInDays != null && nbf != null) {
            var vcIssueTime = nbf.toInstant();

            var dlExpiryDateString =
                    ((IdentityCheckCredential) drivingPermitVc.getCredential())
                            .getCredentialSubject()
                            .getDrivingPermit()
                            .getFirst()
                            .getExpiryDate();

            var dlExpiryDate =
                    LocalDate.parse(dlExpiryDateString).atStartOfDay(LONDON_TIMEZONE).toInstant();

            return dlExpiryDate.isBefore(vcIssueTime)
                    && hasExpired(vcIssueTime, validityDurationInDays, clock);
        }
        return false;
    }

    private static boolean hasExpired(
            Instant vcIssueTime, int validityDurationInDays, Clock clock) {
        var startOfIssueDay =
                vcIssueTime.atZone(LONDON_TIMEZONE).toLocalDate().atStartOfDay(LONDON_TIMEZONE);

        var endOfValidity = startOfIssueDay.plusDays(validityDurationInDays);
        var now = ZonedDateTime.now(clock);

        return endOfValidity.isBefore(now) || endOfValidity.isEqual(now);
    }

    public static boolean hasUnavailableOrNotApplicableFraudCheck(List<VerifiableCredential> vcs) {
        return vcs.stream()
                .filter(vc -> vc.getCri() == Cri.EXPERIAN_FRAUD)
                .anyMatch(
                        vc ->
                                VcHelper.hasFailedFraudCheck(
                                        vc,
                                        Set.of(
                                                APPLICABLE_AUTHORITATIVE_SOURCE,
                                                AVAILABLE_AUTHORITATIVE_SOURCE)));
    }

    public static boolean hasUnavailableFraudCheck(VerifiableCredential vc) {
        return hasFailedFraudCheck(vc, Set.of(AVAILABLE_AUTHORITATIVE_SOURCE));
    }

    private static boolean hasFailedFraudCheck(
            VerifiableCredential vc, Set<CheckDetails.FraudCheckType> failedFraudChecks) {
        if (vc.getCredential() instanceof IdentityCheckCredential identityCheckCredential) {
            return identityCheckCredential.getEvidence().stream()
                    .flatMap(
                            evidence ->
                                    evidence.getFailedCheckDetails() == null
                                            ? Stream.empty()
                                            : evidence.getFailedCheckDetails().stream())
                    .anyMatch(
                            failedCheck -> {
                                CheckDetails.FraudCheckType fraudCheck =
                                        failedCheck.getFraudCheck();
                                return fraudCheck != null && failedFraudChecks.contains(fraudCheck);
                            });
        }
        return false;
    }

    public static Optional<Instant> extractNbf(VerifiableCredential vc) {
        return Optional.ofNullable(vc)
                .map(VerifiableCredential::getClaimsSet)
                .map(JWTClaimsSet::getNotBeforeTime)
                .map(Date::toInstant)
                .or(
                        () -> {
                            LOGGER.warn(
                                    LogHelper.buildLogMessage("Failed to extract nbf from VC."));
                            return Optional.empty();
                        });
    }
}
