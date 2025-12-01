package uk.gov.di.ipv.core.library.useridentity.service;

import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.utils.StringUtils;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.ReturnCode;
import uk.gov.di.ipv.core.library.domain.UserClaims;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.NameHelper;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.AddressCredential;
import uk.gov.di.model.BirthDate;
import uk.gov.di.model.ContraIndicator;
import uk.gov.di.model.DrivingPermitDetails;
import uk.gov.di.model.IdentityCheck;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.IdentityCheckSubject;
import uk.gov.di.model.Name;
import uk.gov.di.model.NamePart;
import uk.gov.di.model.PassportDetails;
import uk.gov.di.model.PersonWithIdentity;
import uk.gov.di.model.PostalAddress;
import uk.gov.di.model.SocialSecurityRecordDetails;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static java.util.Objects.requireNonNullElse;
import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.FILTER_FAILED_VCS_FROM_CREDENTIAL_CLAIM;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_BIRTH_DATE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ISSUER;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_FAMILY_NAME;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_GIVEN_NAMES;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class UserIdentityService {
    private static final List<Cri> CRI_TYPES_EXCLUDED_FOR_NAME_CORRELATION = List.of(ADDRESS);
    private static final List<Cri> CRI_TYPES_EXCLUDED_FOR_DOB_CORRELATION = List.of(ADDRESS);

    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigService configService;
    private final CimitUtilityService cimitUtilityService;

    public UserIdentityService(ConfigService configService) {
        this.configService = configService;
        this.cimitUtilityService = new CimitUtilityService(configService);
    }

    public UserIdentity generateUserIdentity(
            List<VerifiableCredential> vcs,
            String sub,
            Vot achievedVot,
            Vot targetVot,
            List<ContraIndicator> contraIndicators)
            throws HttpResponseExceptionWithErrorBody, UnrecognisedCiException {

        var vcJwtsStream = vcs.stream();
        if (configService.enabled(FILTER_FAILED_VCS_FROM_CREDENTIAL_CLAIM)) {
            vcJwtsStream =
                    vcJwtsStream.filter(
                            vc ->
                                    VcHelper.isSuccessfulVc(vc)
                                            || VcHelper.hasUnavailableOrNotApplicableFraudCheck(
                                                    List.of(vc)));
        }
        var vcJwts = vcJwtsStream.map(VerifiableCredential::getVcString).toList();

        var vtm = configService.getCoreVtmClaim();

        var userIdentityBuilder =
                UserIdentity.UserIdentityBuilder().vcs(vcJwts).sub(sub).vot(achievedVot).vtm(vtm);

        buildUserIdentity(achievedVot, targetVot, contraIndicators, vcs, userIdentityBuilder);

        return userIdentityBuilder.build();
    }

    public Optional<IdentityClaim> findIdentityClaim(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        return findIdentityClaim(vcs, true);
    }

    public Optional<IdentityClaim> findIdentityClaim(
            List<VerifiableCredential> vcs, boolean checkEvidence)
            throws HttpResponseExceptionWithErrorBody {
        var identityClaims = new ArrayList<IdentityClaim>();
        for (var vc : vcs) {
            if (((!checkEvidence || isEvidenceVc(vc)) && VcHelper.isSuccessfulVc(vc))) {
                identityClaims.add(getIdentityClaim(vc));
            }
        }

        if (identityClaims.isEmpty()) {
            LOGGER.warn(LogHelper.buildLogMessage("Failed to find any identity claims in VCs"));
            return Optional.empty();
        }

        Optional<IdentityClaim> claimWithName =
                identityClaims.stream()
                        .filter(identityClaim -> !identityClaim.getName().isEmpty())
                        .findFirst();
        Optional<IdentityClaim> claimWithBirthDate =
                identityClaims.stream()
                        .filter(identityClaim -> !identityClaim.getBirthDate().isEmpty())
                        .findFirst();
        if (claimWithName.isEmpty() || claimWithBirthDate.isEmpty()) {
            LOGGER.error(LogHelper.buildLogMessage("Failed to generate identity claim"));
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.FAILED_TO_GENERATE_IDENTITY_CLAIM);
        }
        IdentityClaim identityClaim =
                new IdentityClaim(
                        claimWithName.get().getName(), claimWithBirthDate.get().getBirthDate());
        return Optional.of(identityClaim);
    }

    public boolean checkRequiresAdditionalEvidence(List<VerifiableCredential> vcs) {
        if (!vcs.isEmpty()) {
            var filterValidVCs = filterValidVCs(vcs);
            if (filterValidVCs.size() == 1) {
                return configService
                        .getOauthCriActiveConnectionConfig(filterValidVCs.get(0).getCri())
                        .isRequiresAdditionalEvidence();
            }
        }
        return false;
    }

    public boolean areNamesAndDobCorrelatedForReverification(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        var successfulVcs = getSuccessfulVcs(vcs);

        if (!checkBirthDateCorrelationInCredentials(successfulVcs)) {
            LOGGER.error(LogHelper.buildErrorMessage(ErrorResponse.FAILED_BIRTHDATE_CORRELATION));
            return false;
        }

        var identityClaimsForNameCorrelation = getIdentityClaimsForNameCorrelation(successfulVcs);
        if (!checkNamesForCorrelation(
                getGivenNamesWithCharAllowanceForCoiCheck(identityClaimsForNameCorrelation))) {
            return false;
        }

        return checkNamesForCorrelation(
                getFamilyNameWithCharAllowanceForCoiCheck(identityClaimsForNameCorrelation));
    }

    public boolean areVcsCorrelated(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        var successfulVcs = getSuccessfulVcs(vcs);

        if (!checkNameAndFamilyNameCorrelationInCredentials(successfulVcs)) {
            LOGGER.info(LogHelper.buildErrorMessage(ErrorResponse.FAILED_NAME_CORRELATION));
            return false;
        }

        if (!checkBirthDateCorrelationInCredentials(successfulVcs)) {
            LOGGER.error(LogHelper.buildErrorMessage(ErrorResponse.FAILED_BIRTHDATE_CORRELATION));
            return false;
        }
        return true;
    }

    public boolean areNamesAndDobCorrelated(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        var successfulVcs = getSuccessfulVcs(vcs);
        var identityClaimsForNameCorrelation = getIdentityClaimsForNameCorrelation(successfulVcs);

        // We check the given names in full, but only the first three characters of the family name
        // This may seem odd, but is deliberate and matches what has been agreed.
        var areGivenNamesCorrelated =
                checkNamesForCorrelation(
                        getNameProperty(
                                identityClaimsForNameCorrelation,
                                NamePart.NamePartType.GIVEN_NAME));

        var isFamilyNameCorrelated =
                checkNamesForCorrelation(
                        getFamilyNameWithCharAllowanceForCoiCheck(
                                identityClaimsForNameCorrelation));

        // Given names AND family name cannot both be changed
        if (!areGivenNamesCorrelated && !isFamilyNameCorrelated) {
            return false;
        }

        var isBirthDateCorrelated = checkBirthDateCorrelationInCredentials(successfulVcs);
        LOGGER.info(
                LogHelper.buildLogMessage("Names and DOB correlated")
                        .with(LOG_GIVEN_NAMES.getFieldName(), areGivenNamesCorrelated)
                        .with(LOG_FAMILY_NAME.getFieldName(), isFamilyNameCorrelated)
                        .with(LOG_BIRTH_DATE.getFieldName(), isBirthDateCorrelated));

        return (areGivenNamesCorrelated && isBirthDateCorrelated)
                || (isFamilyNameCorrelated && isBirthDateCorrelated);
    }

    private List<VerifiableCredential> getSuccessfulVcs(List<VerifiableCredential> vcs) {
        return vcs.stream().filter(VcHelper::isSuccessfulVc).toList();
    }

    private void buildUserIdentity(
            Vot achievedVot,
            Vot targetVot,
            List<ContraIndicator> contraIndicators,
            List<VerifiableCredential> vcs,
            UserIdentity.UserIdentityBuilder userIdentityBuilder)
            throws HttpResponseExceptionWithErrorBody {
        if (Vot.P0.equals(achievedVot)) {
            userIdentityBuilder.returnCode(getFailReturnCode(contraIndicators, targetVot));
        } else {
            var successfulVcs = vcs.stream().filter(VcHelper::isSuccessfulVc).toList();
            var userClaims = getUserClaims(successfulVcs);
            userIdentityBuilder
                    .identityClaim(userClaims.getIdentityClaim())
                    .addressClaim(userClaims.getAddressClaim())
                    .passportClaim(userClaims.getPassportClaim())
                    .drivingPermitClaim(userClaims.getDrivingPermitClaim())
                    .ninoClaim(userClaims.getNinoClaim())
                    .returnCode(getSuccessReturnCode(contraIndicators));
        }
    }

    public UserClaims getUserClaims(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        var userClaimsBuilder = UserClaims.builder();

        Optional<IdentityClaim> identityClaim = findIdentityClaim(vcs);
        identityClaim.ifPresent(userClaimsBuilder::identityClaim);

        Optional<List<PostalAddress>> addressClaim = getAddressClaim(vcs);
        addressClaim.ifPresent(userClaimsBuilder::addressClaim);

        Optional<List<PassportDetails>> passportClaim =
                getFirstClaim(vcs, IdentityCheckSubject::getPassport);
        passportClaim.ifPresent(userClaimsBuilder::passportClaim);

        Optional<List<DrivingPermitDetails>> drivingPermitClaim =
                getFirstClaim(vcs, IdentityCheckSubject::getDrivingPermit);
        drivingPermitClaim.ifPresent(
                drivingPermit -> {
                    drivingPermit.forEach(
                            permit -> {
                                permit.setFullAddress(null);
                                permit.setIssueDate(null);
                            });
                    userClaimsBuilder.drivingPermitClaim(drivingPermit);
                });

        Optional<List<SocialSecurityRecordDetails>> ninoClaim =
                getFirstClaim(vcs, IdentityCheckSubject::getSocialSecurityRecord);
        ninoClaim.ifPresent(userClaimsBuilder::ninoClaim);

        return userClaimsBuilder.build();
    }

    private boolean checkNameAndFamilyNameCorrelationInCredentials(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        List<IdentityClaim> identityClaims = getIdentityClaimsForNameCorrelation(vcs);
        var normalisedNames = getNormalisedFullNamesFromCredentials(identityClaims);
        return normalisedNames.stream().distinct().count() <= 1;
    }

    private boolean checkBirthDateCorrelationInCredentials(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        List<IdentityClaim> identityClaims = getIdentityClaimsForBirthDateCorrelation(vcs);
        return identityClaims.stream()
                        .map(IdentityClaim::getBirthDate)
                        .flatMap(List::stream)
                        .map(BirthDate::getValue)
                        .distinct()
                        .count()
                <= 1;
    }

    public boolean checkNamesForCorrelation(List<String> userFullNames) {
        return userFullNames.stream().map(NameHelper::normaliseNameForComparison).distinct().count()
                <= 1;
    }

    private List<IdentityClaim> getIdentityClaimsForNameCorrelation(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        List<IdentityClaim> identityClaims = new ArrayList<>();
        for (var vc : vcs) {
            IdentityClaim identityClaim = getIdentityClaim(vc);
            String missingNames = getMissingNames(identityClaim.getName());
            if (!missingNames.isBlank()) {
                if (CRI_TYPES_EXCLUDED_FOR_NAME_CORRELATION.contains(vc.getCri())) {
                    continue;
                }
                addLogMessage(vc, "Names missing from VC: " + missingNames);
                throw new HttpResponseExceptionWithErrorBody(
                        SC_SERVER_ERROR, ErrorResponse.FAILED_NAME_CORRELATION);
            }
            identityClaims.add(identityClaim);
        }
        return identityClaims;
    }

    private List<IdentityClaim> getIdentityClaimsForBirthDateCorrelation(
            List<VerifiableCredential> vcs) throws HttpResponseExceptionWithErrorBody {
        List<IdentityClaim> identityClaims = new ArrayList<>();
        for (var vc : vcs) {
            IdentityClaim identityClaim = getIdentityClaim(vc);
            if (isBirthDateEmpty(identityClaim.getBirthDate())) {
                if (CRI_TYPES_EXCLUDED_FOR_DOB_CORRELATION.contains(vc.getCri())) {
                    continue;
                }
                addLogMessage(vc, "Birthdate property is missing from VC");
                throw new HttpResponseExceptionWithErrorBody(
                        SC_SERVER_ERROR, ErrorResponse.FAILED_BIRTHDATE_CORRELATION);
            }
            identityClaims.add(identityClaim);
        }
        return identityClaims;
    }

    private List<String> getNormalisedFullNamesFromCredentials(List<IdentityClaim> identityClaims) {
        return identityClaims.stream()
                .flatMap(claim -> claim.getName().stream())
                .map(NameHelper::getNormalisedFullNameForComparison)
                .toList();
    }

    private List<String> getFamilyNameWithCharAllowanceForCoiCheck(
            List<IdentityClaim> identityClaims) {
        return getShortenedNamesForCoiCheck(
                identityClaims,
                configService.getConfiguration().getSelf().getCoi().getFamilyNameChars(),
                NamePart.NamePartType.FAMILY_NAME);
    }

    private List<String> getGivenNamesWithCharAllowanceForCoiCheck(
            List<IdentityClaim> identityClaims) {
        return getShortenedNamesForCoiCheck(
                identityClaims,
                configService.getConfiguration().getSelf().getCoi().getGivenNameChars(),
                NamePart.NamePartType.GIVEN_NAME);
    }

    private List<String> getShortenedNamesForCoiCheck(
            List<IdentityClaim> identityClaims,
            Integer charCount,
            NamePart.NamePartType namePartType) {
        return getNameProperty(identityClaims, namePartType).stream()
                .map(name -> StringUtils.substring(name, 0, charCount))
                .toList();
    }

    private List<String> getNameProperty(
            List<IdentityClaim> identityClaims, NamePart.NamePartType nameProperty) {
        return identityClaims.stream()
                .map(IdentityClaim::getNameParts)
                .map(
                        nameParts ->
                                nameParts.stream()
                                        .filter(namePart -> nameProperty.equals(namePart.getType()))
                                        .map(NamePart::getValue)
                                        .collect(Collectors.joining(" ")))
                .toList();
    }

    private boolean isBirthDateEmpty(List<BirthDate> birthDates) {
        return CollectionUtils.isEmpty(birthDates)
                || birthDates.stream().map(BirthDate::getValue).allMatch(StringUtils::isEmpty);
    }

    private List<ReturnCode> getFailReturnCode(
            List<ContraIndicator> contraIndicators, Vot targetVot) throws UnrecognisedCiException {
        return cimitUtilityService.isBreachingCiThreshold(contraIndicators, targetVot)
                ? mapCisToReturnCodes(contraIndicators)
                : List.of(
                        new ReturnCode(
                                configService
                                        .getConfiguration()
                                        .getSelf()
                                        .getReturnCodes()
                                        .get("nonCiBreachingP0")));
    }

    private List<ReturnCode> getSuccessReturnCode(List<ContraIndicator> contraIndicators)
            throws UnrecognisedCiException {
        return mapCisToReturnCodes(contraIndicators).stream()
                .filter(
                        returnCode ->
                                configService
                                        .getConfiguration()
                                        .getSelf()
                                        .getReturnCodes()
                                        .get("alwaysRequired")
                                        .contains(returnCode.code()))
                .toList();
    }

    private List<ReturnCode> mapCisToReturnCodes(List<ContraIndicator> contraIndicators)
            throws UnrecognisedCiException {
        return contraIndicators.stream()
                .map(ContraIndicator::getCode)
                .map(
                        ciCode ->
                                Optional.ofNullable(
                                                configService
                                                        .getContraIndicatorConfigMap()
                                                        .get(ciCode))
                                        .orElseThrow(
                                                () ->
                                                        new UnrecognisedCiException(
                                                                "CI code not found")))
                .map(ContraIndicatorConfig::getReturnCode)
                .distinct()
                .sorted()
                .map(ReturnCode::new)
                .toList();
    }

    private IdentityClaim getIdentityClaim(VerifiableCredential vc) {
        if (vc.getCredential().getCredentialSubject() instanceof PersonWithIdentity person) {

            List<Name> names = requireNonNullElse(person.getName(), List.of());

            List<BirthDate> birthDates = requireNonNullElse(person.getBirthDate(), List.of());

            return new IdentityClaim(names, birthDates);

        } else {
            return new IdentityClaim(List.of(), List.of());
        }
    }

    public Vot getVot(VerifiableCredential vc) throws IllegalArgumentException, ParseException {
        return Vot.valueOf(vc.getClaimsSet().getStringClaim(VOT_CLAIM_NAME));
    }

    public Optional<List<PostalAddress>> getAddressClaim(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        var addressVc = findVc(ADDRESS, vcs);

        if (addressVc.isEmpty()) {
            return Optional.empty();
        }

        if (addressVc.get().getCredential() instanceof AddressCredential addressCredential) {
            var credentialSubject = addressCredential.getCredentialSubject();

            if (credentialSubject == null) {
                LOGGER.error(LogHelper.buildErrorMessage(ErrorResponse.CREDENTIAL_SUBJECT_MISSING));
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM);
            }

            var address = credentialSubject.getAddress();

            if (isNullOrEmpty(address)) {
                LOGGER.error(
                        LogHelper.buildLogMessage(
                                "Address property missing from VC or empty address property."));
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM);
            }

            return Optional.of(address);
        } else {
            LOGGER.error(LogHelper.buildLogMessage("Credential must be an Address credential."));
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM);
        }
    }

    private <T> Optional<List<T>> getFirstClaim(
            List<VerifiableCredential> vcs, Function<IdentityCheckSubject, List<T>> getClaim) {
        for (var vc : vcs) {
            if (vc.getCredential() instanceof IdentityCheckCredential identityCheckCredential) {
                var credentialSubject = identityCheckCredential.getCredentialSubject();

                if (credentialSubject == null) {
                    continue;
                }

                var claim = getClaim.apply(credentialSubject);

                if (!isNullOrEmpty(claim)) {
                    return Optional.of(claim);
                }
            }
        }
        return Optional.empty();
    }

    private Optional<VerifiableCredential> findVc(Cri cri, List<VerifiableCredential> vcs) {
        return vcs.stream().filter(credential -> credential.getCri().equals(cri)).findFirst();
    }

    private boolean isEvidenceVc(VerifiableCredential vc) {
        if (vc.getCredential() instanceof IdentityCheckCredential identityCheckCredential) {
            var vcEvidence = identityCheckCredential.getEvidence();
            if (vcEvidence == null) {
                return false;
            }

            for (IdentityCheck evidence : vcEvidence) {
                if (isNonZeroInt(evidence.getValidityScore())
                        && isNonZeroInt(evidence.getStrengthScore())) {
                    return true;
                }
            }

            return false;
        }
        return false;
    }

    private boolean isNonZeroInt(Integer value) {
        return value != null && value != 0;
    }

    private List<VerifiableCredential> filterValidVCs(List<VerifiableCredential> vcs) {
        return vcs.stream().filter(this::isEvidenceVc).toList();
    }

    private String getMissingNames(List<Name> names) {
        if (CollectionUtils.isEmpty(names)) {
            return "Name list";
        }

        return names.stream()
                .flatMap(name -> name.getNameParts().stream())
                .filter(namePart -> StringUtils.isBlank(namePart.getValue()))
                .map(
                        namePart ->
                                String.format(
                                        "%s is '%s'",
                                        namePart.getType(),
                                        namePart.getValue() == null ? "null" : namePart.getValue()))
                .collect(Collectors.joining("and"));
    }

    private void addLogMessage(VerifiableCredential vc, String error) {
        StringMapMessage logMessage =
                new StringMapMessage()
                        .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), error)
                        .with(LOG_CRI_ISSUER.getFieldName(), vc.getCri().getId());
        LOGGER.warn(logMessage);
    }
}
