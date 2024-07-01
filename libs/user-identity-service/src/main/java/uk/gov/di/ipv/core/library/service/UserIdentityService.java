package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.utils.StringUtils;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.domain.ReturnCode;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.NoVcStatusForIssuerException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.model.IdentityCheckCredential;

import java.text.Normalizer;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COI_CHECK_FAMILY_NAME_CHARS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_VTM_CLAIM;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.RETURN_CODES_ALWAYS_REQUIRED;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.RETURN_CODES_NON_CI_BREACHING_P0;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.BAV;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.Cri.DRIVING_LICENCE;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.Cri.NINO;
import static uk.gov.di.ipv.core.library.domain.Cri.PASSPORT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_STRENGTH;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_VALIDITY;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ISSUER;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_CODE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class UserIdentityService {
    public static final String NAME_PROPERTY_NAME = "name";
    public static final String BIRTH_DATE_PROPERTY_NAME = "birthDate";
    private static final List<String> PASSPORT_CRI_TYPES = List.of(PASSPORT.getId(), DCMAW.getId());
    private static final List<String> DRIVING_PERMIT_CRI_TYPES =
            List.of(DCMAW.getId(), DRIVING_LICENCE.getId());

    private static final List<String> CRI_TYPES_EXCLUDED_FOR_NAME_CORRELATION =
            List.of(ADDRESS.getId());
    private static final List<String> CRI_TYPES_EXCLUDED_FOR_DOB_CORRELATION =
            List.of(ADDRESS.getId(), BAV.getId());

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String ADDRESS_PROPERTY_NAME = "address";
    private static final String NINO_PROPERTY_NAME = "socialSecurityRecord";
    private static final String PASSPORT_PROPERTY_NAME = "passport";
    private static final String DRIVING_PERMIT_PROPERTY_NAME = "drivingPermit";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Pattern DIACRITIC_CHECK_PATTERN = Pattern.compile("\\p{M}");
    private static final Pattern IGNORE_SOME_CHARACTERS_PATTERN = Pattern.compile("[\\s'-]+");

    public static final String GIVEN_NAME_PROPERTY_NAME = "GivenName";
    public static final String FAMILY_NAME_PROPERTY_NAME = "FamilyName";

    private final ConfigService configService;
    private final CiMitUtilityService ciMitUtilityService;

    public UserIdentityService(ConfigService configService) {
        this.configService = configService;
        this.ciMitUtilityService = new CiMitUtilityService(configService);
        VcHelper.setConfigService(configService);
    }

    public UserIdentity generateUserIdentity(
            List<VerifiableCredential> vcs, String sub, Vot vot, ContraIndicators contraIndicators)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException,
                    UnrecognisedCiException {
        var profileType = vot.getProfileType();
        var vcJwts = vcs.stream().map(VerifiableCredential::getVcString).toList();

        var vtm = configService.getSsmParameter(CORE_VTM_CLAIM);

        var userIdentityBuilder = UserIdentity.builder().vcs(vcJwts).sub(sub).vot(vot).vtm(vtm);

        buildUserIdentityBasedOnProfileType(
                vot, contraIndicators, profileType, vcs, userIdentityBuilder);

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
                    500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM);
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
                        .getOauthCriActiveConnectionConfig(filterValidVCs.get(0).getCri().getId())
                        .isRequiresAdditionalEvidence();
            }
        }
        return false;
    }

    public boolean isVcSuccessful(List<VcStatusDto> currentVcStatuses, String criIss)
            throws NoVcStatusForIssuerException {
        return currentVcStatuses.stream()
                .filter(vcStatusDto -> vcStatusDto.getCriIss().equals(criIss))
                .findFirst()
                .orElseThrow(
                        () ->
                                new NoVcStatusForIssuerException(
                                        String.format(
                                                "No VC status found for issuer '%s'", criIss)))
                .getIsSuccessfulVc();
    }

    public boolean areVcsCorrelated(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        var successfulVcs = getSuccessfulVcs(vcs);

        if (!checkNameAndFamilyNameCorrelationInCredentials(successfulVcs)) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_ERROR_CODE.getFieldName(),
                                    ErrorResponse.FAILED_NAME_CORRELATION.getCode())
                            .with(
                                    LOG_ERROR_DESCRIPTION.getFieldName(),
                                    ErrorResponse.FAILED_NAME_CORRELATION.getMessage()));

            return false;
        }

        if (!checkBirthDateCorrelationInCredentials(successfulVcs)) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_ERROR_CODE.getFieldName(),
                                    ErrorResponse.FAILED_BIRTHDATE_CORRELATION.getCode())
                            .with(
                                    LOG_ERROR_DESCRIPTION.getFieldName(),
                                    ErrorResponse.FAILED_BIRTHDATE_CORRELATION.getMessage()));

            return false;
        }
        return true;
    }

    public boolean areGivenNamesAndDobCorrelated(List<VerifiableCredential> vcs)
            throws CredentialParseException, HttpResponseExceptionWithErrorBody {
        var successfulVcs = getSuccessfulVcs(vcs);

        if (!checkNamesForCorrelation(
                getNameProperty(
                        getIdentityClaimsForNameCorrelation(successfulVcs),
                        GIVEN_NAME_PROPERTY_NAME))) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_ERROR_CODE.getFieldName(),
                                    ErrorResponse.FAILED_NAME_CORRELATION.getCode())
                            .with(
                                    LOG_ERROR_DESCRIPTION.getFieldName(),
                                    ErrorResponse.FAILED_NAME_CORRELATION.getMessage()));

            return false;
        }

        if (!checkBirthDateCorrelationInCredentials(successfulVcs)) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_ERROR_CODE.getFieldName(),
                                    ErrorResponse.FAILED_BIRTHDATE_CORRELATION.getCode())
                            .with(
                                    LOG_ERROR_DESCRIPTION.getFieldName(),
                                    ErrorResponse.FAILED_BIRTHDATE_CORRELATION.getMessage()));

            return false;
        }
        return true;
    }

    public boolean areFamilyNameAndDobCorrelatedForCoiCheck(List<VerifiableCredential> vcs)
            throws CredentialParseException, HttpResponseExceptionWithErrorBody {
        var successfulVcs = getSuccessfulVcs(vcs);

        if (!checkNamesForCorrelation(
                getFamilyNameForCoiCheck(getIdentityClaimsForNameCorrelation(successfulVcs)))) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_ERROR_CODE.getFieldName(),
                                    ErrorResponse.FAILED_NAME_CORRELATION.getCode())
                            .with(
                                    LOG_ERROR_DESCRIPTION.getFieldName(),
                                    ErrorResponse.FAILED_NAME_CORRELATION.getMessage()));

            return false;
        }

        if (!checkBirthDateCorrelationInCredentials(successfulVcs)) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_ERROR_CODE.getFieldName(),
                                    ErrorResponse.FAILED_BIRTHDATE_CORRELATION.getCode())
                            .with(
                                    LOG_ERROR_DESCRIPTION.getFieldName(),
                                    ErrorResponse.FAILED_BIRTHDATE_CORRELATION.getMessage()));

            return false;
        }
        return true;
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
            Vot vot,
            ContraIndicators contraIndicators,
            ProfileType profileType,
            List<VerifiableCredential> vcs,
            UserIdentity.UserIdentityBuilder userIdentityBuilder)
            throws CredentialParseException, HttpResponseExceptionWithErrorBody {
        var successfulVcs = new ArrayList<VerifiableCredential>();
        for (var vc : vcs) {
            if (VcHelper.isSuccessfulVc(vc)) {
                successfulVcs.add(vc);
            }
        }
        if (Vot.P0.equals(vot)) {
            userIdentityBuilder.returnCode(getFailReturnCode(contraIndicators));
        } else {
            addUserIdentityClaims(profileType, vcs, userIdentityBuilder, successfulVcs);
            userIdentityBuilder.returnCode(getSuccessReturnCode(contraIndicators));
        }
    }

    private void addUserIdentityClaims(
            ProfileType profileType,
            List<VerifiableCredential> vcs,
            UserIdentity.UserIdentityBuilder userIdentityBuilder,
            List<VerifiableCredential> successfulVcs)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        Optional<IdentityClaim> identityClaim = findIdentityClaim(successfulVcs);
        identityClaim.ifPresent(userIdentityBuilder::identityClaim);

        if (profileType.equals(ProfileType.GPG45)) {
            Optional<JsonNode> addressClaim = generateAddressClaim(vcs);
            addressClaim.ifPresent(userIdentityBuilder::addressClaim);

            Optional<JsonNode> passportClaim = generatePassportClaim(successfulVcs);
            passportClaim.ifPresent(userIdentityBuilder::passportClaim);

            Optional<JsonNode> drivingPermitClaim = generateDrivingPermitClaim(successfulVcs);
            drivingPermitClaim.ifPresent(userIdentityBuilder::drivingPermitClaim);
        }

        Optional<JsonNode> ninoClaim = generateNinoClaim(successfulVcs, profileType);
        ninoClaim.ifPresent(userIdentityBuilder::ninoClaim);
    }

    private boolean checkNameAndFamilyNameCorrelationInCredentials(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        List<IdentityClaim> identityClaims = getIdentityClaimsForNameCorrelation(vcs);
        return checkNamesForCorrelation(getFullNamesFromCredentials(identityClaims));
    }

    private boolean checkBirthDateCorrelationInCredentials(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
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
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        List<IdentityClaim> identityClaims = new ArrayList<>();
        for (var vc : vcs) {
            IdentityClaim identityClaim = getIdentityClaim(vc);
            String missingNames = getMissingNames(identityClaim.getName());
            if (!missingNames.isBlank()) {
                if (CRI_TYPES_EXCLUDED_FOR_NAME_CORRELATION.contains(vc.getCri().getId())) {
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
            List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        List<IdentityClaim> identityClaims = new ArrayList<>();
        for (var vc : vcs) {
            IdentityClaim identityClaim = getIdentityClaim(vc);
            if (isBirthDateEmpty(identityClaim.getBirthDate())) {
                if (CRI_TYPES_EXCLUDED_FOR_DOB_CORRELATION.contains(vc.getCri().getId())) {
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
                .map(Name::getNameParts)
                .map(
                        nameParts -> {
                            String givenNames =
                                    nameParts.stream()
                                            .filter(
                                                    namePart ->
                                                            GIVEN_NAME_PROPERTY_NAME.equals(
                                                                    namePart.getType()))
                                            .map(NameParts::getValue)
                                            .collect(Collectors.joining(" "));

                            String familyNames =
                                    nameParts.stream()
                                            .filter(
                                                    namePart ->
                                                            FAMILY_NAME_PROPERTY_NAME.equals(
                                                                    namePart.getType()))
                                            .map(NameParts::getValue)
                                            .collect(Collectors.joining(" "));

                            return givenNames + " " + familyNames;
                        })
                .map(String::trim)
                .toList();
    }

    private List<String> getFamilyNameForCoiCheck(List<IdentityClaim> identityClaims) {
        return getNameProperty(identityClaims, FAMILY_NAME_PROPERTY_NAME).stream()
                .map(
                        familyName ->
                                StringUtils.substring(
                                        familyName,
                                        0,
                                        Integer.parseInt(
                                                configService.getSsmParameter(
                                                        COI_CHECK_FAMILY_NAME_CHARS))))
                .toList();
    }

    private List<String> getNameProperty(List<IdentityClaim> identityClaims, String nameProperty) {
        return identityClaims.stream()
                .map(IdentityClaim::getNameParts)
                .map(
                        nameParts ->
                                nameParts.stream()
                                        .filter(namePart -> nameProperty.equals(namePart.getType()))
                                        .map(NameParts::getValue)
                                        .collect(Collectors.joining(" ")))
                .toList();
    }

    private boolean isBirthDateEmpty(List<BirthDate> birthDates) {
        return CollectionUtils.isEmpty(birthDates)
                || birthDates.stream().map(BirthDate::getValue).allMatch(StringUtils::isEmpty);
    }

    private List<ReturnCode> getFailReturnCode(ContraIndicators contraIndicators)
            throws UnrecognisedCiException {
        return ciMitUtilityService.isBreachingCiThreshold(contraIndicators)
                ? mapCisToReturnCodes(contraIndicators)
                : List.of(
                        new ReturnCode(
                                configService.getSsmParameter(RETURN_CODES_NON_CI_BREACHING_P0)));
    }

    private List<ReturnCode> getSuccessReturnCode(ContraIndicators contraIndicators)
            throws UnrecognisedCiException {
        return mapCisToReturnCodes(contraIndicators).stream()
                .filter(
                        returnCode ->
                                configService
                                        .getSsmParameter(RETURN_CODES_ALWAYS_REQUIRED)
                                        .contains(returnCode.code()))
                .toList();
    }

    private List<ReturnCode> mapCisToReturnCodes(ContraIndicators contraIndicators)
            throws UnrecognisedCiException {
        return contraIndicators.getUsersContraIndicators().stream()
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

    private JsonNode getVcClaimNode(String credential, String node)
            throws CredentialParseException {
        try {
            return OBJECT_MAPPER
                    .readTree(SignedJWT.parse(credential).getPayload().toString())
                    .path(VC_CLAIM)
                    .path(node);
        } catch (JsonProcessingException | ParseException e) {
            throw new CredentialParseException(
                    "Encountered a parsing error while attempting to parse VC store item: "
                            + e.getMessage());
        }
    }

    private IdentityClaim getIdentityClaim(VerifiableCredential vc) {
        var credentialSubject =
                ((IdentityCheckCredential) vc.getCredential()).getCredentialSubject();

        var nameParts =
                credentialSubject.getName().stream()
                        .map(
                                name ->
                                        name.getNameParts().stream()
                                                .map(
                                                        np ->
                                                                new NameParts(
                                                                        np.getValue(),
                                                                        np.getType().toString()))
                                                .toList())
                        .flatMap(Collection::stream)
                        .toList();

        var names = List.of(new Name(nameParts));

        var birthDates =
                credentialSubject.getBirthDate().stream()
                        .map(bd -> new BirthDate(bd.getValue()))
                        .toList();

        return new IdentityClaim(names, birthDates);
    }

    public Vot getVot(VerifiableCredential vc) throws IllegalArgumentException, ParseException {
        return Vot.valueOf(vc.getClaimsSet().getStringClaim(VOT_CLAIM_NAME));
    }

    private Optional<JsonNode> generateAddressClaim(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        var addressVc = findVc(ADDRESS.getId(), vcs);

        if (addressVc.isEmpty()) {
            LOGGER.warn(LogHelper.buildLogMessage("Failed to find Address CRI credential"));
            return Optional.empty();
        }

        var addressNode =
                extractSubjectDetailFromVc(
                        ADDRESS_PROPERTY_NAME,
                        addressVc.get(),
                        "Error while parsing Address CRI credential",
                        ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM);

        if (addressNode.isMissingNode()) {
            LOGGER.error(LogHelper.buildLogMessage("Address property is missing from address VC"));
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM);
        }

        return Optional.of(addressNode);
    }

    private Optional<JsonNode> generateNinoClaim(
            List<VerifiableCredential> vcs, ProfileType profileType)
            throws HttpResponseExceptionWithErrorBody {
        String criToExtractFrom =
                profileType.equals(ProfileType.GPG45) ? NINO.getId() : HMRC_MIGRATION.getId();
        var ninoVc = findVc(criToExtractFrom, vcs);

        if (ninoVc.isEmpty()) {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Failed to find appropriate CRI credential to extract "
                                    + NINO_PROPERTY_NAME));
            return Optional.empty();
        }

        var ninoNode =
                extractSubjectDetailFromVc(
                        NINO_PROPERTY_NAME,
                        ninoVc.get(),
                        "Error while parsing Nino CRI credential",
                        ErrorResponse.FAILED_TO_GENERATE_NINO_CLAIM);

        if (ninoNode.isMissingNode()) {
            StringMapMessage mapMessage =
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Nino property is missing from VC")
                            .with(LOG_CRI_ISSUER.getFieldName(), ninoVc.get().getCri().getId());
            LOGGER.warn(mapMessage);

            return Optional.empty();
        }

        return Optional.of(ninoNode);
    }

    private Optional<JsonNode> generatePassportClaim(List<VerifiableCredential> vcs)
            throws HttpResponseExceptionWithErrorBody {
        var passportVc = findVc(PASSPORT_CRI_TYPES, vcs);

        if (passportVc.isEmpty()) {
            LOGGER.warn(LogHelper.buildLogMessage("Failed to find Passport CRI credential"));
            return Optional.empty();
        }

        var passportNode =
                extractSubjectDetailFromVc(
                        PASSPORT_PROPERTY_NAME,
                        passportVc.get(),
                        "Error while parsing Passport CRI credential",
                        ErrorResponse.FAILED_TO_GENERATE_PASSPORT_CLAIM);

        if (passportNode.isMissingNode()) {
            StringMapMessage mapMessage =
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Passport property is missing from VC")
                            .with(LOG_CRI_ISSUER.getFieldName(), passportVc.get().getCri().getId());
            LOGGER.warn(mapMessage);

            return Optional.empty();
        }

        return Optional.of(passportNode);
    }

    private Optional<JsonNode> generateDrivingPermitClaim(
            List<VerifiableCredential> verifiableCredentials)
            throws HttpResponseExceptionWithErrorBody {
        var drivingPermitVc = findVc(DRIVING_PERMIT_CRI_TYPES, verifiableCredentials);

        if (drivingPermitVc.isEmpty()) {
            LOGGER.warn(LogHelper.buildLogMessage("Failed to find Driving Permit CRI credential"));
            return Optional.empty();
        }

        var drivingPermitNode =
                extractSubjectDetailFromVc(
                        DRIVING_PERMIT_PROPERTY_NAME,
                        drivingPermitVc.get(),
                        "Error while parsing Driving Permit CRI credential",
                        ErrorResponse.FAILED_TO_GENERATE_DRIVING_PERMIT_CLAIM);

        if (drivingPermitNode.isMissingNode()) {
            StringMapMessage mapMessage =
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Driving Permit property is missing from VC")
                            .with(
                                    LOG_CRI_ISSUER.getFieldName(),
                                    drivingPermitVc.get().getCri().getId());
            LOGGER.warn(mapMessage);

            return Optional.empty();
        }

        if (drivingPermitNode instanceof ArrayNode) {
            ((ObjectNode) drivingPermitNode.get(0)).remove("fullAddress");
            ((ObjectNode) drivingPermitNode.get(0)).remove("issueDate");
        }

        return Optional.of(drivingPermitNode);
    }

    private Optional<VerifiableCredential> findVc(String criName, List<VerifiableCredential> vcs) {
        return vcs.stream()
                .filter(credential -> credential.getCri().getId().equals(criName))
                .findFirst();
    }

    private Optional<VerifiableCredential> findVc(
            List<String> criNames, List<VerifiableCredential> vcs) {
        return vcs.stream()
                .filter(credential -> criNames.contains(credential.getCri().getId()))
                .findFirst();
    }

    private JsonNode extractSubjectDetailFromVc(
            String detailName,
            VerifiableCredential vc,
            String errorLog,
            ErrorResponse errorResponse)
            throws HttpResponseExceptionWithErrorBody {
        try {
            return getVcClaimNode(vc.getVcString(), VC_CREDENTIAL_SUBJECT).path(detailName);
        } catch (CredentialParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage(errorLog, e));
            throw new HttpResponseExceptionWithErrorBody(SC_SERVER_ERROR, errorResponse);
        }
    }

    private boolean isEvidenceVc(VerifiableCredential vc) throws CredentialParseException {
        JsonNode vcEvidenceNode = getVcClaimNode(vc.getVcString(), VC_EVIDENCE);
        for (JsonNode evidence : vcEvidenceNode) {
            if (isNonZeroInt(evidence.path(VC_EVIDENCE_VALIDITY))
                    && isNonZeroInt(evidence.path(VC_EVIDENCE_STRENGTH))) {
                return true;
            }
        }
        return false;
    }

    private boolean isNonZeroInt(JsonNode node) {
        return node.isInt() && node.asInt() != 0;
    }

    private List<VerifiableCredential> filterValidVCs(List<VerifiableCredential> vcs) {
        return vcs.stream()
                .filter(
                        vc -> {
                            try {
                                return isEvidenceVc(vc);
                            } catch (CredentialParseException e) {
                                return false;
                            }
                        })
                .toList();
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
