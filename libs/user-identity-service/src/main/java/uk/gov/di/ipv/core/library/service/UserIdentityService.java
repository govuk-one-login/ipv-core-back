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

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ALWAYS_REQUIRED_EXIT_CODES;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_VTM_CLAIM;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EXIT_CODES;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME;
import static uk.gov.di.ipv.core.library.domain.CriConstants.*;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ISSUER;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class UserIdentityService {
    public static final String NAME_PROPERTY_NAME = "name";
    public static final String BIRTH_DATE_PROPERTY_NAME = "birthDate";
    private static final List<String> PASSPORT_CRI_TYPES = List.of(PASSPORT_CRI, DCMAW_CRI);
    private static final List<String> DRIVING_PERMIT_CRI_TYPES =
            List.of(DCMAW_CRI, DRIVING_LICENCE_CRI);
    public static final List<String> EVIDENCE_CRI_TYPES =
            List.of(PASSPORT_CRI, DCMAW_CRI, DRIVING_LICENCE_CRI, F2F_CRI);

    public static final List<String> CRI_TYPES_EXCLUDED_FOR_NAME_CORRELATION = List.of(ADDRESS_CRI);
    public static final List<String> CRI_TYPES_EXCLUDED_FOR_DOB_CORRELATION =
            List.of(ADDRESS_CRI, BAV_CRI);

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String ADDRESS_PROPERTY_NAME = "address";
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

    public void deleteVcStoreItems(String userId) {
        List<VcStoreItem> vcStoreItems = dataStore.getItems(userId);
        if (!vcStoreItems.isEmpty()) {
            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Deleting existing issued VCs.")
                            .with(
                                    LogHelper.LogField.LOG_NUMBER_OF_VCS.getFieldName(),
                                    String.valueOf(vcStoreItems.size()));
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
            Optional<IdentityClaim> identityClaim = generateIdentityClaim(successfulVCStoreItems);
            identityClaim.ifPresent(userIdentityBuilder::identityClaim);

            Optional<JsonNode> addressClaim = generateAddressClaim(vcStoreItems);
            addressClaim.ifPresent(userIdentityBuilder::addressClaim);

            Optional<JsonNode> passportClaim = generatePassportClaim(successfulVCStoreItems);
            passportClaim.ifPresent(userIdentityBuilder::passportClaim);

            Optional<JsonNode> drivingPermitClaim =
                    generateDrivingPermitClaim(successfulVCStoreItems);
            drivingPermitClaim.ifPresent(userIdentityBuilder::drivingPermitClaim);
            if (configService.enabled(EXIT_CODES)) {
                userIdentityBuilder.exitCode(toAlwaysRequiredExitCode(contraIndicators));
            }
        } else {
            if (configService.enabled(EXIT_CODES)
                    && contraIndicators.getContraIndicatorScore(
                                    configService.getContraIndicatorConfigMap())
                            >= Integer.parseInt(
                                    configService.getSsmParameter(CI_SCORING_THRESHOLD))) {
                userIdentityBuilder.exitCode(toExitCode(contraIndicators));
            }
        }

        return userIdentityBuilder.build();
    }

    private List<String> toExitCode(ContraIndicators contraIndicators)
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

    private List<String> toAlwaysRequiredExitCode(ContraIndicators contraIndicators)
            throws UnrecognisedCiException {
        return toExitCode(contraIndicators).stream()
                .filter(configService.getSsmParameter(ALWAYS_REQUIRED_EXIT_CODES)::contains)
                .toList();
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

    private JsonNode getVCClaimNode(String credential) throws HttpResponseExceptionWithErrorBody {
        try {
            return objectMapper
                    .readTree(SignedJWT.parse(credential).getPayload().toString())
                    .path(VC_CLAIM)
                    .path(VC_CREDENTIAL_SUBJECT);
        } catch (ParseException | JsonProcessingException e) {
            LOGGER.error("Failed to parse VC JWT because: {}", e.getMessage());
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM);
        }
    }

    private <T> T getJsonProperty(
            JsonNode jsonNode,
            String propertyName,
            String credentialIssuer,
            CollectionType valueType,
            boolean validateCorrelation)
            throws HttpResponseExceptionWithErrorBody {
        JsonNode propertyNode = jsonNode.path(propertyName);
        if (!validateCorrelation && propertyNode.isMissingNode()) {
            LOGGER.error("Property [{}] is missing from [{}] VC.", propertyName, credentialIssuer);
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM);
        } else if (propertyNode.isMissingNode()) {
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

    private IdentityClaim getIdentityClaim(
            String credential, String credentialIssuer, boolean validateCorrelation)
            throws HttpResponseExceptionWithErrorBody {
        JsonNode vcClaimNode = getVCClaimNode(credential);
        List<Name> names =
                getJsonProperty(
                        vcClaimNode,
                        NAME_PROPERTY_NAME,
                        credentialIssuer,
                        objectMapper
                                .getTypeFactory()
                                .constructCollectionType(List.class, Name.class),
                        validateCorrelation);
        List<BirthDate> birthDates =
                getJsonProperty(
                        vcClaimNode,
                        BIRTH_DATE_PROPERTY_NAME,
                        credentialIssuer,
                        objectMapper
                                .getTypeFactory()
                                .constructCollectionType(List.class, BirthDate.class),
                        validateCorrelation);

        return new IdentityClaim(names, birthDates);
    }

    private Optional<IdentityClaim> generateIdentityClaim(List<VcStoreItem> successfulVCStoreItems)
            throws HttpResponseExceptionWithErrorBody {
        for (VcStoreItem item : successfulVCStoreItems) {
            if (EVIDENCE_CRI_TYPES.contains(item.getCredentialIssuer())) {
                return Optional.of(
                        getIdentityClaim(item.getCredential(), item.getCredentialIssuer(), false));
            }
        }
        LOGGER.warn("Failed to generate identity claim");
        return Optional.empty();
    }

    private Optional<JsonNode> generateAddressClaim(List<VcStoreItem> vcStoreItems)
            throws HttpResponseExceptionWithErrorBody {
        var addressStoreItem = findStoreItem(ADDRESS_CRI, vcStoreItems);

        if (addressStoreItem.isEmpty()) {
            LOGGER.warn("Failed to find Address CRI credential");
            return Optional.empty();
        }

        var addressNode =
                extractCriNodeFromCredential(
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

    private Optional<JsonNode> generatePassportClaim(List<VcStoreItem> successfulVCStoreItems)
            throws HttpResponseExceptionWithErrorBody {
        var passportVc = findStoreItem(PASSPORT_CRI_TYPES, successfulVCStoreItems);

        if (passportVc.isEmpty()) {
            LOGGER.warn("Failed to find Passport CRI credential");
            return Optional.empty();
        }

        var passportNode =
                extractCriNodeFromCredential(
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
                extractCriNodeFromCredential(
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

    private JsonNode extractCriNodeFromCredential(
            String criName,
            VcStoreItem ninoCredentialItem,
            String errorLog,
            ErrorResponse errorResponse)
            throws HttpResponseExceptionWithErrorBody {
        try {
            return objectMapper
                    .readTree(
                            SignedJWT.parse(ninoCredentialItem.getCredential())
                                    .getPayload()
                                    .toString())
                    .path(VC_CLAIM)
                    .path(VC_CREDENTIAL_SUBJECT)
                    .path(criName);
        } catch (JsonProcessingException | ParseException e) {
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
            List<VcStoreItem> vcStoreItems) throws HttpResponseExceptionWithErrorBody {
        List<IdentityClaim> identityClaims = new ArrayList<>();
        for (VcStoreItem item : vcStoreItems) {
            IdentityClaim identityClaim =
                    getIdentityClaim(item.getCredential(), item.getCredentialIssuer(), true);
            if (isBirthDateEmpty(identityClaim.getBirthDate())) {
                if (CRI_TYPES_EXCLUDED_FOR_DOB_CORRELATION.contains(item.getCredentialIssuer())) {
                    continue;
                }
                addLogMessage(item, "Birthdate property is missing from VC");
            }
            identityClaims.add(identityClaim);
        }
        return identityClaims;
    }

    public boolean isBirthDateEmpty(List<BirthDate> birthDates) {
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
            throws HttpResponseExceptionWithErrorBody {
        List<IdentityClaim> identityClaims = new ArrayList<>();
        for (VcStoreItem item : vcStoreItems) {
            IdentityClaim identityClaim =
                    getIdentityClaim(item.getCredential(), item.getCredentialIssuer(), true);
            if (isNamesEmpty(identityClaim.getName())) {
                if (CRI_TYPES_EXCLUDED_FOR_NAME_CORRELATION.contains(item.getCredentialIssuer())) {
                    continue;
                }
                addLogMessage(item, "Name property is missing from VC");
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

    private void addLogMessage(VcStoreItem item, String error) {
        StringMapMessage logMessage =
                new StringMapMessage()
                        .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), error)
                        .with(LOG_CRI_ISSUER.getFieldName(), item.getCredentialIssuer());
        LOGGER.warn(logMessage);
    }
}
