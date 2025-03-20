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
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.domain.ReturnCode;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
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

import java.text.Normalizer;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static java.util.Objects.requireNonNullElse;
import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COI_CHECK_FAMILY_NAME_CHARS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COI_CHECK_GIVEN_NAME_CHARS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_VTM_CLAIM;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.RETURN_CODES_ALWAYS_REQUIRED;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.RETURN_CODES_NON_CI_BREACHING_P0;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.Cri.DRIVING_LICENCE;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.Cri.NINO;
import static uk.gov.di.ipv.core.library.domain.Cri.PASSPORT;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_BIRTH_DATE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ISSUER;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_FAMILY_NAME;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_GIVEN_NAMES;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class UserIdentityService {
    private static final List<Cri> PASSPORT_CRI_TYPES = List.of(PASSPORT, DCMAW, F2F);
    private static final List<Cri> DRIVING_PERMIT_CRI_TYPES = List.of(DRIVING_LICENCE, DCMAW, F2F);

    private static final List<Cri> CRI_TYPES_EXCLUDED_FOR_NAME_CORRELATION = List.of(ADDRESS);
    private static final List<Cri> CRI_TYPES_EXCLUDED_FOR_DOB_CORRELATION = List.of(ADDRESS);

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String NINO_PROPERTY_NAME = "socialSecurityRecord";
    private static final Pattern DIACRITIC_CHECK_PATTERN = Pattern.compile("\\p{M}");
    private static final Pattern IGNORE_SOME_CHARACTERS_PATTERN = Pattern.compile("[\\s'-]+");

    private static final String MUST_BE_IDENTITYCHECK_MESSAGE =
            "Credential must be an IdentityCheck credential.";

    private final ConfigService configService;
    private final CimitUtilityService cimitUtilityService;

    public UserIdentityService(ConfigService configService) {
        this.configService = configService;
        this.cimitUtilityService = new CimitUtilityService(configService);
        VcHelper.setConfigService(configService);
    }

    public UserIdentity generateUserIdentity(
            List<VerifiableCredential> vcs,
            String sub,
            Vot achievedVot,
            Vot targetVot,
            List<ContraIndicator> contraIndicators)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException,
                    UnrecognisedCiException {
        var profileType = achievedVot.getProfileType();
        var vcJwts = vcs.stream().map(VerifiableCredential::getVcString).toList();

        var vtm = configService.getParameter(CORE_VTM_CLAIM);

        var userIdentityBuilder =
                UserIdentity.builder().vcs(vcJwts).sub(sub).vot(achievedVot).vtm(vtm);

        buildUserIdentityBasedOnProfileType(
                achievedVot, targetVot, contraIndicators, profileType, vcs, userIdentityBuilder);

        return userIdentityBuilder.build();
    }

    public Optional<IdentityClaim> findIdentityClaim(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        return findIdentityClaim(vcs, true);
    }

    public Optional<IdentityClaim> findIdentityClaim(
            List<VerifiableCredential> vcs, boolean checkEvidence)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        var identityClaims = new ArrayList<IdentityClaim>();
        for (var vc : vcs) {
            try {
                if (VcHelper.isOperationalProfileVc(vc)
                        || ((!checkEvidence || isEvidenceVc(vc)) && VcHelper.isSuccessfulVc(vc))) {
                    identityClaims.add(getIdentityClaim(vc));
                }
            } catch (ParseException e) {
                throw new CredentialParseException(
                        "Encountered a parsing error while attempting to parse VC store item");
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
        var successfulVcs = new ArrayList<VerifiableCredential>();
        for (var vc : VcHelper.filterVCBasedOnProfileType(vcs, ProfileType.GPG45)) {
            if (VcHelper.isSuccessfulVc(vc)) {
                successfulVcs.add(vc);
            }
        }
        return successfulVcs;
    }

    private void buildUserIdentityBasedOnProfileType(
            Vot achievedVot,
            Vot targetVot,
            List<ContraIndicator> contraIndicators,
            ProfileType profileType,
            List<VerifiableCredential> vcs,
            UserIdentity.UserIdentityBuilder userIdentityBuilder)
            throws CredentialParseException, HttpResponseExceptionWithErrorBody {
        if (Vot.P0.equals(achievedVot)) {
            userIdentityBuilder.returnCode(getFailReturnCode(contraIndicators, targetVot));
        } else {
            var successfulVcs = vcs.stream().filter(VcHelper::isSuccessfulVc).toList();
            addUserIdentityClaims(profileType, successfulVcs, userIdentityBuilder);
            userIdentityBuilder.returnCode(getSuccessReturnCode(contraIndicators));
        }
    }

    private void addUserIdentityClaims(
            ProfileType profileType,
            List<VerifiableCredential> vcs,
            UserIdentity.UserIdentityBuilder userIdentityBuilder)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        Optional<IdentityClaim> identityClaim = findIdentityClaim(vcs);
        identityClaim.ifPresent(userIdentityBuilder::identityClaim);

        if (profileType.equals(ProfileType.GPG45)) {
            Optional<List<PostalAddress>> addressClaim = generateAddressClaim(vcs);
            addressClaim.ifPresent(userIdentityBuilder::addressClaim);

            Optional<List<PassportDetails>> passportClaim = generatePassportClaim(vcs);
            passportClaim.ifPresent(userIdentityBuilder::passportClaim);

            Optional<List<DrivingPermitDetails>> drivingPermitClaim =
                    generateDrivingPermitClaim(vcs);
            drivingPermitClaim.ifPresent(userIdentityBuilder::drivingPermitClaim);
        }

        Optional<List<SocialSecurityRecordDetails>> ninoClaim = generateNinoClaim(vcs, profileType);
        ninoClaim.ifPresent(userIdentityBuilder::ninoClaim);
    }

    private boolean checkNameAndFamilyNameCorrelationInCredentials(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        List<IdentityClaim> identityClaims = getIdentityClaimsForNameCorrelation(vcs);
        return checkNamesForCorrelation(getFullNamesFromCredentials(identityClaims));
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
        return userFullNames.stream()
                        .map(n -> Normalizer.normalize(n, Normalizer.Form.NFD))
                        .map(n -> DIACRITIC_CHECK_PATTERN.matcher(n).replaceAll(""))
                        .map(n -> IGNORE_SOME_CHARACTERS_PATTERN.matcher(n).replaceAll(""))
                        .map(String::toLowerCase)
                        .distinct()
                        .count()
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

    private List<String> getFullNamesFromCredentials(List<IdentityClaim> identityClaims) {
        return identityClaims.stream()
                .flatMap(claim -> claim.getName().stream())
                .map(NameHelper::getFullName)
                .toList();
    }

    private List<String> getFamilyNameWithCharAllowanceForCoiCheck(
            List<IdentityClaim> identityClaims) {
        return getShortenedNamesForCoiCheck(
                identityClaims,
                Integer.parseInt(configService.getParameter(COI_CHECK_FAMILY_NAME_CHARS)),
                NamePart.NamePartType.FAMILY_NAME);
    }

    private List<String> getGivenNamesWithCharAllowanceForCoiCheck(
            List<IdentityClaim> identityClaims) {
        return getShortenedNamesForCoiCheck(
                identityClaims,
                Integer.parseInt(configService.getParameter(COI_CHECK_GIVEN_NAME_CHARS)),
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
                                configService.getParameter(RETURN_CODES_NON_CI_BREACHING_P0)));
    }

    private List<ReturnCode> getSuccessReturnCode(List<ContraIndicator> contraIndicators)
            throws UnrecognisedCiException {
        return mapCisToReturnCodes(contraIndicators).stream()
                .filter(
                        returnCode ->
                                configService
                                        .getParameter(RETURN_CODES_ALWAYS_REQUIRED)
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

    public Optional<List<PostalAddress>> generateAddressClaim(List<VerifiableCredential> vcs)
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

    private Optional<List<SocialSecurityRecordDetails>> generateNinoClaim(
            List<VerifiableCredential> vcs, ProfileType profileType)
            throws HttpResponseExceptionWithErrorBody {
        var criToExtractFrom = profileType.equals(ProfileType.GPG45) ? NINO : HMRC_MIGRATION;
        var ninoVc = findVc(criToExtractFrom, vcs);

        if (ninoVc.isEmpty()) {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Failed to find appropriate CRI credential to extract "
                                    + NINO_PROPERTY_NAME));
            return Optional.empty();
        }

        if (ninoVc.get().getCredential()
                instanceof IdentityCheckCredential identityCheckCredential) {
            var credentialSubject = getIdentityCheckSubjectOrThrowError(identityCheckCredential);

            var nino = credentialSubject.getSocialSecurityRecord();

            if (isNullOrEmpty(nino)) {
                return Optional.empty();
            }

            return Optional.of(nino);
        } else {
            LOGGER.warn(
                    LogHelper.buildLogMessage(MUST_BE_IDENTITYCHECK_MESSAGE)
                            .with(LOG_CRI_ISSUER.getFieldName(), ninoVc.get().getCri().getId()));
            return Optional.empty();
        }
    }

    private Optional<List<PassportDetails>> generatePassportClaim(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        var passportVc = findVc(PASSPORT_CRI_TYPES, vcs);

        if (passportVc.isEmpty()) {
            return Optional.empty();
        }

        if (passportVc.get().getCredential()
                instanceof IdentityCheckCredential identityCheckCredential) {

            var credentialSubject = getIdentityCheckSubjectOrThrowError(identityCheckCredential);

            var passport = credentialSubject.getPassport();

            if (isNullOrEmpty(passport)) {
                return Optional.empty();
            }

            return Optional.of(passport);
        } else {
            LOGGER.warn(
                    LogHelper.buildLogMessage(MUST_BE_IDENTITYCHECK_MESSAGE)
                            .with(
                                    LOG_CRI_ISSUER.getFieldName(),
                                    passportVc.get().getCri().getId()));
            return Optional.empty();
        }
    }

    private Optional<List<DrivingPermitDetails>> generateDrivingPermitClaim(
            List<VerifiableCredential> verifiableCredentials)
            throws HttpResponseExceptionWithErrorBody {
        var drivingPermitVc = findVc(DRIVING_PERMIT_CRI_TYPES, verifiableCredentials);

        if (drivingPermitVc.isEmpty()) {
            return Optional.empty();
        }

        if (drivingPermitVc.get().getCredential()
                instanceof IdentityCheckCredential identityCheckCredential) {

            var credentialSubject = getIdentityCheckSubjectOrThrowError(identityCheckCredential);

            var drivingPermit = credentialSubject.getDrivingPermit();

            if (isNullOrEmpty(drivingPermit)) {
                return Optional.empty();
            }

            drivingPermit.forEach(
                    permit -> {
                        permit.setFullAddress(null);
                        permit.setIssueDate(null);
                    });

            return Optional.of(drivingPermit);
        } else {
            LOGGER.warn(
                    LogHelper.buildLogMessage(MUST_BE_IDENTITYCHECK_MESSAGE)
                            .with(
                                    LOG_CRI_ISSUER.getFieldName(),
                                    drivingPermitVc.get().getCri().getId()));
            return Optional.empty();
        }
    }

    private Optional<VerifiableCredential> findVc(Cri cri, List<VerifiableCredential> vcs) {
        return vcs.stream().filter(credential -> credential.getCri().equals(cri)).findFirst();
    }

    private Optional<VerifiableCredential> findVc(List<Cri> cris, List<VerifiableCredential> vcs) {
        return vcs.stream().filter(credential -> cris.contains(credential.getCri())).findFirst();
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

    private IdentityCheckSubject getIdentityCheckSubjectOrThrowError(
            IdentityCheckCredential identityCheckCredential)
            throws HttpResponseExceptionWithErrorBody {
        var credentialSubject = identityCheckCredential.getCredentialSubject();

        if (credentialSubject == null) {
            LOGGER.error(LogHelper.buildErrorMessage(ErrorResponse.CREDENTIAL_SUBJECT_MISSING));
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.CREDENTIAL_SUBJECT_MISSING);
        }

        return credentialSubject;
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
