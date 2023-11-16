package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.utils.StringUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.domain.VectorOfTrust;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.NoVcStatusForIssuerException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;

import java.text.Normalizer;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_VTM_CLAIM;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.EXIT_CODES_ALWAYS_REQUIRED;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.EXIT_CODES_NON_CI_BREACHING_P0;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.BAV_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DRIVING_LICENCE_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.NINO_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_STRENGTH;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_VALIDITY;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ISSUER;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_CODE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class UserIdentityService {
    public static final String NAME_PROPERTY_NAME = "name";
    public static final String BIRTH_DATE_PROPERTY_NAME = "birthDate";
    private static final List<String> PASSPORT_CRI_TYPES = List.of(PASSPORT_CRI, DCMAW_CRI);
    private static final List<String> DRIVING_PERMIT_CRI_TYPES =
            List.of(DCMAW_CRI, DRIVING_LICENCE_CRI);

    private static final List<String> CRI_TYPES_EXCLUDED_FOR_NAME_CORRELATION =
            List.of(ADDRESS_CRI);
    private static final List<String> CRI_TYPES_EXCLUDED_FOR_DOB_CORRELATION =
            List.of(ADDRESS_CRI, BAV_CRI);

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String ADDRESS_PROPERTY_NAME = "address";
    private static final String NINO_PROPERTY_NAME = "socialSecurityRecord";
    private static final String PASSPORT_PROPERTY_NAME = "passport";
    private static final String DRIVING_PERMIT_PROPERTY_NAME = "drivingPermit";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final Pattern DIACRITIC_CHECK_PATTERN = Pattern.compile("\\p{M}");
    private static final Pattern IGNORE_SOME_CHARACTERS_PATTERN = Pattern.compile("[\\s'-]+");

    public static final String GIVEN_NAME_PROPERTY_NAME = "GivenName";
    public static final String FAMILY_NAME_PROPERTY_NAME = "FamilyName";

    private final ConfigService configService;
    private final DataStore<VcStoreItem> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public UserIdentityService(ConfigService configService) {
        this.configService = configService;
        boolean isRunningLocally = this.configService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(
                                USER_ISSUED_CREDENTIALS_TABLE_NAME),
                        VcStoreItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configService);
        VcHelper.setConfigService(configService);
    }

    public UserIdentityService(ConfigService configService, DataStore<VcStoreItem> dataStore) {
        this.configService = configService;
        this.dataStore = dataStore;
        VcHelper.setConfigService(configService);
    }

    public List<String> getUserIssuedCredentials(String userId) {
        List<VcStoreItem> vcStoreItems = dataStore.getItems(userId);

        return vcStoreItems.stream().map(VcStoreItem::getCredential).toList();
    }

    public void deleteVcStoreItems(String userId, Boolean isUserInitiated) {
        List<VcStoreItem> vcStoreItems = dataStore.getItems(userId);
        if (!vcStoreItems.isEmpty()) {
            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Deleting existing issued VCs.")
                            .with(
                                    LogHelper.LogField.LOG_NUMBER_OF_VCS.getFieldName(),
                                    String.valueOf(vcStoreItems.size()))
                            .with(
                                    LogHelper.LogField.LOG_IS_USER_INITIATED.getFieldName(),
                                    String.valueOf(isUserInitiated));
            LOGGER.info(message);
        }
        for (VcStoreItem item : vcStoreItems) {
            dataStore.delete(item.getUserId(), item.getCredentialIssuer());
        }
    }

    public List<VcStoreItem> getVcStoreItems(String userId) {
        return dataStore.getItems(userId);
    }

    public VcStoreItem getVcStoreItem(String userId, String criId) {
        return dataStore.getItem(userId, criId);
    }

    public UserIdentity generateUserIdentity(
            String userId, String sub, String vot, ContraIndicators contraIndicators)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException,
                    UnrecognisedCiException {
        List<VcStoreItem> vcStoreItems = dataStore.getItems(userId);

        List<String> vcJwts = vcStoreItems.stream().map(VcStoreItem::getCredential).toList();

        String vtm = configService.getSsmParameter(CORE_VTM_CLAIM);

        UserIdentity.UserIdentityBuilder userIdentityBuilder =
                UserIdentity.builder().vcs(vcJwts).sub(sub).vot(vot).vtm(vtm);

        if (vot.equals(VectorOfTrust.P2.toString())) {
            final List<VcStoreItem> successfulVCStoreItems =
                    getSuccessfulVCStoreItems(vcStoreItems);
            Optional<IdentityClaim> identityClaim = findIdentityClaim(successfulVCStoreItems);
            identityClaim.ifPresent(userIdentityBuilder::identityClaim);

            Optional<JsonNode> addressClaim = generateAddressClaim(vcStoreItems);
            addressClaim.ifPresent(userIdentityBuilder::addressClaim);

            Optional<JsonNode> passportClaim = generatePassportClaim(successfulVCStoreItems);
            passportClaim.ifPresent(userIdentityBuilder::passportClaim);

            Optional<JsonNode> drivingPermitClaim =
                    generateDrivingPermitClaim(successfulVCStoreItems);
            drivingPermitClaim.ifPresent(userIdentityBuilder::drivingPermitClaim);

            Optional<JsonNode> ninoClaim = generateNinoClaim(successfulVCStoreItems);
            ninoClaim.ifPresent(userIdentityBuilder::ninoClaim);

            userIdentityBuilder.exitCode(getSuccessExitCode(contraIndicators));
        } else {
            userIdentityBuilder.exitCode(getFailExitCode(contraIndicators));
        }

        return userIdentityBuilder.build();
    }

    private List<String> getFailExitCode(ContraIndicators contraIndicators)
            throws UnrecognisedCiException {
        return breachingCiThreshold(contraIndicators)
                ? mapCisToExitCodes(contraIndicators)
                : List.of(configService.getSsmParameter(EXIT_CODES_NON_CI_BREACHING_P0));
    }

    private List<String> getSuccessExitCode(ContraIndicators contraIndicators)
            throws UnrecognisedCiException {
        return mapCisToExitCodes(contraIndicators).stream()
                .filter(configService.getSsmParameter(EXIT_CODES_ALWAYS_REQUIRED)::contains)
                .toList();
    }

    private List<String> mapCisToExitCodes(ContraIndicators contraIndicators)
            throws UnrecognisedCiException {
        return contraIndicators.getContraIndicatorsMap().values().stream()
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
                .map(ContraIndicatorConfig::getExitCode)
                .distinct()
                .sorted()
                .toList();
    }

    public boolean breachingCiThreshold(ContraIndicators contraIndicators) {
        return contraIndicators.getContraIndicatorScore(configService.getContraIndicatorConfigMap())
                > Integer.parseInt(configService.getSsmParameter(CI_SCORING_THRESHOLD));
    }

    private List<VcStoreItem> getSuccessfulVCStoreItems(List<VcStoreItem> vcStoreItems)
            throws CredentialParseException {
        final List<VcStoreItem> successfulVCStoreItems = new ArrayList<>();
        for (VcStoreItem vcStoreItem : vcStoreItems) {
            try {
                if (VcHelper.isSuccessfulVc(SignedJWT.parse(vcStoreItem.getCredential()))) {
                    successfulVCStoreItems.add(vcStoreItem);
                }
            } catch (ParseException e) {
                throw new CredentialParseException(
                        "Encountered a parsing error while attempting to parse successful VC Store items.");
            }
        }
        return successfulVCStoreItems;
    }

    public Optional<Boolean> getVCSuccessStatus(String userId, String criId) throws ParseException {
        VcStoreItem vcStoreItem = getVcStoreItem(userId, criId);
        if (vcStoreItem != null) {
            SignedJWT vc = SignedJWT.parse(vcStoreItem.getCredential());
            return Optional.of(VcHelper.isSuccessfulVc(vc));
        }
        LOGGER.info("vcStoreItem for CRI '{}' was null", criId);
        return Optional.empty();
    }

    private JsonNode getVCClaimNode(String credential, String node)
            throws CredentialParseException {
        try {
            return objectMapper
                    .readTree(SignedJWT.parse(credential).getPayload().toString())
                    .path(VC_CLAIM)
                    .path(node);
        } catch (JsonProcessingException | ParseException e) {
            throw new CredentialParseException(
                    "Encountered a parsing error while attempting to parse VC store item: "
                            + e.getMessage());
        }
    }

    private <T> T getJsonProperty(JsonNode jsonNode, String propertyName, CollectionType valueType)
            throws HttpResponseExceptionWithErrorBody {
        JsonNode propertyNode = jsonNode.path(propertyName);
        if (propertyNode.isMissingNode()) {
            try {
                return objectMapper.readValue(new JSONArray().toJSONString(), valueType);
            } catch (JsonProcessingException e) {
                LOGGER.error("Failed to generate empty list: {}", e.getMessage());
                throw new HttpResponseExceptionWithErrorBody(
                        500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM);
            }
        }
        try {
            return objectMapper.treeToValue(propertyNode, valueType);
        } catch (JsonProcessingException e) {
            LOGGER.error("Failed to parse VC JWT because: {}", e.getMessage());
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM);
        }
    }

    private IdentityClaim getIdentityClaim(String credential)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        JsonNode vcClaimNode = getVCClaimNode(credential, VC_CREDENTIAL_SUBJECT);
        List<Name> names =
                getJsonProperty(
                        vcClaimNode,
                        NAME_PROPERTY_NAME,
                        objectMapper
                                .getTypeFactory()
                                .constructCollectionType(List.class, Name.class));
        List<BirthDate> birthDates =
                getJsonProperty(
                        vcClaimNode,
                        BIRTH_DATE_PROPERTY_NAME,
                        objectMapper
                                .getTypeFactory()
                                .constructCollectionType(List.class, BirthDate.class));

        return new IdentityClaim(names, birthDates);
    }

    public Optional<IdentityClaim> findIdentityClaim(List<VcStoreItem> vcStoreItems)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        List<IdentityClaim> identityClaims = new ArrayList<>();
        for (VcStoreItem vcStoreItem : vcStoreItems) {
            try {
                if (isEvidenceVc(vcStoreItem)
                        && VcHelper.isSuccessfulVc(SignedJWT.parse(vcStoreItem.getCredential()))) {
                    identityClaims.add(getIdentityClaim(vcStoreItem.getCredential()));
                }
            } catch (ParseException e) {
                throw new CredentialParseException(
                        "Encountered a parsing error while attempting to parse VC store item");
            }
        }

        if (identityClaims.isEmpty()) {
            LOGGER.warn("Failed to generate identity claim");
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
            LOGGER.error("Failed to generate identity claim");
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM);
        }
        IdentityClaim identityClaim =
                new IdentityClaim(
                        claimWithName.get().getName(), claimWithBirthDate.get().getBirthDate());
        return Optional.of(identityClaim);
    }

    private Optional<JsonNode> generateAddressClaim(List<VcStoreItem> vcStoreItems)
            throws HttpResponseExceptionWithErrorBody {
        var addressStoreItem = findStoreItem(ADDRESS_CRI, vcStoreItems);

        if (addressStoreItem.isEmpty()) {
            LOGGER.warn("Failed to find Address CRI credential");
            return Optional.empty();
        }

        var addressNode =
                extractSubjectDetailFromVc(
                        ADDRESS_PROPERTY_NAME,
                        addressStoreItem.get(),
                        "Error while parsing Address CRI credential",
                        ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM);

        if (addressNode.isMissingNode()) {
            LOGGER.error("Address property is missing from address VC");
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM);
        }

        return Optional.of(addressNode);
    }

    private Optional<JsonNode> generateNinoClaim(List<VcStoreItem> successfulVCStoreItems)
            throws HttpResponseExceptionWithErrorBody {
        var ninoStoreItem = findStoreItem(NINO_CRI, successfulVCStoreItems);

        if (ninoStoreItem.isEmpty()) {
            LOGGER.warn("Failed to find Nino CRI credential");
            return Optional.empty();
        }

        var ninoNode =
                extractSubjectDetailFromVc(
                        NINO_PROPERTY_NAME,
                        ninoStoreItem.get(),
                        "Error while parsing Nino CRI credential",
                        ErrorResponse.FAILED_TO_GENERATE_NINO_CLAIM);

        if (ninoNode.isMissingNode()) {
            StringMapMessage mapMessage =
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Nino property is missing from VC")
                            .with(
                                    LOG_CRI_ISSUER.getFieldName(),
                                    ninoStoreItem.get().getCredentialIssuer());
            LOGGER.warn(mapMessage);

            return Optional.empty();
        }

        return Optional.of(ninoNode);
    }

    private Optional<JsonNode> generatePassportClaim(List<VcStoreItem> successfulVCStoreItems)
            throws HttpResponseExceptionWithErrorBody {
        var passportVc = findStoreItem(PASSPORT_CRI_TYPES, successfulVCStoreItems);

        if (passportVc.isEmpty()) {
            LOGGER.warn("Failed to find Passport CRI credential");
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
                            .with(
                                    LOG_CRI_ISSUER.getFieldName(),
                                    passportVc.get().getCredentialIssuer());
            LOGGER.warn(mapMessage);

            return Optional.empty();
        }

        return Optional.of(passportNode);
    }

    private Optional<JsonNode> generateDrivingPermitClaim(List<VcStoreItem> successfulVCStoreItems)
            throws HttpResponseExceptionWithErrorBody {
        var drivingPermitVc = findStoreItem(DRIVING_PERMIT_CRI_TYPES, successfulVCStoreItems);

        if (drivingPermitVc.isEmpty()) {
            LOGGER.warn("Failed to find Driving Permit CRI credential");
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
                                    drivingPermitVc.get().getCredentialIssuer());
            LOGGER.warn(mapMessage);

            return Optional.empty();
        }

        if (drivingPermitNode instanceof ArrayNode) {
            ((ObjectNode) drivingPermitNode.get(0)).remove("fullAddress");
            ((ObjectNode) drivingPermitNode.get(0)).remove("issueDate");
        }

        return Optional.of(drivingPermitNode);
    }

    private Optional<VcStoreItem> findStoreItem(String criName, List<VcStoreItem> vcStoreItems) {
        return vcStoreItems.stream()
                .filter(credential -> credential.getCredentialIssuer().equals(criName))
                .findFirst();
    }

    private Optional<VcStoreItem> findStoreItem(
            List<String> criNames, List<VcStoreItem> vcStoreItems) {
        return vcStoreItems.stream()
                .filter(credential -> criNames.contains(credential.getCredentialIssuer()))
                .findFirst();
    }

    private JsonNode extractSubjectDetailFromVc(
            String detailName,
            VcStoreItem credentialItem,
            String errorLog,
            ErrorResponse errorResponse)
            throws HttpResponseExceptionWithErrorBody {
        try {
            return getVCClaimNode(credentialItem.getCredential(), VC_CREDENTIAL_SUBJECT)
                    .path(detailName);
        } catch (CredentialParseException e) {
            LOGGER.error("{}: '{}'", errorLog, e.getMessage());
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, errorResponse);
        }
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

    private boolean isEvidenceVc(VcStoreItem item) throws CredentialParseException {
        JsonNode vcEvidenceNode = getVCClaimNode(item.getCredential(), VC_EVIDENCE);
        for (JsonNode evidence : vcEvidenceNode) {
            if (evidence.path(VC_EVIDENCE_VALIDITY).isInt()
                    && evidence.path(VC_EVIDENCE_STRENGTH).isInt()) {
                return true;
            }
        }
        return false;
    }

    public boolean checkBirthDateCorrelationInCredentials(String userId)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        final List<VcStoreItem> successfulVCStoreItems =
                getSuccessfulVCStoreItems(getVcStoreItems(userId));
        List<IdentityClaim> identityClaims =
                getIdentityClaimsForBirthDateCorrelation(successfulVCStoreItems);
        return identityClaims.stream()
                        .map(IdentityClaim::getBirthDate)
                        .flatMap(List::stream)
                        .map(BirthDate::getValue)
                        .distinct()
                        .count()
                <= 1;
    }

    private List<IdentityClaim> getIdentityClaimsForBirthDateCorrelation(
            List<VcStoreItem> vcStoreItems)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        List<IdentityClaim> identityClaims = new ArrayList<>();
        for (VcStoreItem item : vcStoreItems) {
            IdentityClaim identityClaim = getIdentityClaim(item.getCredential());
            if (isBirthDateEmpty(identityClaim.getBirthDate())) {
                if (CRI_TYPES_EXCLUDED_FOR_DOB_CORRELATION.contains(item.getCredentialIssuer())) {
                    continue;
                }
                addLogMessage(item, "Birthdate property is missing from VC");
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_BIRTHDATE_CORRELATION);
            }
            identityClaims.add(identityClaim);
        }
        return identityClaims;
    }

    private boolean isBirthDateEmpty(List<BirthDate> birthDates) {
        return CollectionUtils.isEmpty(birthDates)
                || birthDates.stream().map(BirthDate::getValue).allMatch(StringUtils::isEmpty);
    }

    public boolean checkNameAndFamilyNameCorrelationInCredentials(String userId)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        final List<VcStoreItem> successfulVCStoreItems =
                getSuccessfulVCStoreItems(getVcStoreItems(userId));
        List<IdentityClaim> identityClaims =
                getIdentityClaimsForNameCorrelation(successfulVCStoreItems);
        return checkNamesForCorrelation(getFullNamesFromCredentials(identityClaims));
    }

    private List<IdentityClaim> getIdentityClaimsForNameCorrelation(List<VcStoreItem> vcStoreItems)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        List<IdentityClaim> identityClaims = new ArrayList<>();
        for (VcStoreItem item : vcStoreItems) {
            IdentityClaim identityClaim = getIdentityClaim(item.getCredential());
            if (isNamesEmpty(identityClaim.getName())) {
                if (CRI_TYPES_EXCLUDED_FOR_NAME_CORRELATION.contains(item.getCredentialIssuer())) {
                    continue;
                }
                addLogMessage(item, "Name property is missing from VC");
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_NAME_CORRELATION);
            }
            identityClaims.add(identityClaim);
        }
        return identityClaims;
    }

    private boolean isNamesEmpty(List<Name> names) {
        return CollectionUtils.isEmpty(names)
                || names.stream()
                        .flatMap(name -> name.getNameParts().stream())
                        .map(NameParts::getValue)
                        .allMatch(StringUtils::isEmpty);
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

    private List<String> getFullNamesFromCredentials(List<IdentityClaim> identityClaims) {
        return identityClaims.stream()
                .flatMap(id -> id.getName().stream())
                .map(Name::getNameParts)
                .map(
                        nameParts -> {
                            String givenNames =
                                    nameParts.stream()
                                            .filter(
                                                    nameParts1 ->
                                                            GIVEN_NAME_PROPERTY_NAME.equals(
                                                                            nameParts1.getType())
                                                                    && !nameParts1
                                                                            .getValue()
                                                                            .equals(""))
                                            .map(NameParts::getValue)
                                            .collect(Collectors.joining(" "));

                            String familyNames =
                                    nameParts.stream()
                                            .filter(
                                                    nameParts1 ->
                                                            FAMILY_NAME_PROPERTY_NAME.equals(
                                                                            nameParts1.getType())
                                                                    && !nameParts1
                                                                            .getValue()
                                                                            .equals(""))
                                            .map(NameParts::getValue)
                                            .collect(Collectors.joining(" "));

                            return givenNames + " " + familyNames;
                        })
                .map(String::trim)
                .toList();
    }

    public boolean areVcsCorrelated(String userId)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        if (!checkNameAndFamilyNameCorrelationInCredentials(userId)) {
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

        if (!checkBirthDateCorrelationInCredentials(userId)) {
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

    private void addLogMessage(VcStoreItem item, String error) {
        StringMapMessage logMessage =
                new StringMapMessage()
                        .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), error)
                        .with(LOG_CRI_ISSUER.getFieldName(), item.getCredentialIssuer());
        LOGGER.warn(logMessage);
    }
}
