package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.domain.VectorOfTrust;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_VTM_CLAIM;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;

public class UserIdentityService {
    public static final String NAME_PROPERTY_NAME = "name";
    public static final String BIRTH_DATE_PROPERTY_NAME = "birthDate";
    public static final String ADDRESS_PROPERTY_NAME = "address";
    public static final List<String> ADDRESS_CRI_TYPES =
            List.of(ADDRESS_PROPERTY_NAME, "stubAddress");
    public static final String UK_PASSPORT = "ukPassport";
    public static final String STUB_UK_PASSPORT = "stubUkPassport";
    public static final String DCMAW = "dcmaw";
    public static final String STUB_DCMAW = "stubDcmaw";
    public static final String DRIVING_LICENCE = "drivingLicence";
    public static final String STUB_DRIVING_LICENCE = "stubDrivingLicence";
    private static final List<String> PASSPORT_CRI_TYPES =
            List.of(UK_PASSPORT, STUB_UK_PASSPORT, DCMAW, STUB_DCMAW);
    private static final List<String> DRIVING_PERMIT_CRI_TYPES =
            List.of(DCMAW, STUB_DCMAW, DRIVING_LICENCE, STUB_DRIVING_LICENCE);
    public static final List<String> EVIDENCE_CRI_TYPES =
            List.of(
                    UK_PASSPORT,
                    STUB_UK_PASSPORT,
                    DCMAW,
                    STUB_DCMAW,
                    DRIVING_LICENCE,
                    STUB_DRIVING_LICENCE);

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String PASSPORT_PROPERTY_NAME = "passport";
    private static final String DRIVING_PERMIT_PROPERTY_NAME = "drivingPermit";
    private static final ObjectMapper objectMapper = new ObjectMapper();

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
    }

    public UserIdentityService(ConfigService configService, DataStore<VcStoreItem> dataStore) {
        this.configService = configService;
        this.dataStore = dataStore;
    }

    public List<String> getUserIssuedCredentials(String userId) {
        List<VcStoreItem> vcStoreItems = dataStore.getItems(userId);

        return vcStoreItems.stream().map(VcStoreItem::getCredential).collect(Collectors.toList());
    }

    public void deleteVcStoreItemsIfAnyExpired(String userId) {
        Instant nowPlusSessionTimeout =
                Instant.now()
                        .plusSeconds(
                                Long.parseLong(
                                        configService.getSsmParameter(BACKEND_SESSION_TIMEOUT)));
        List<VcStoreItem> expiredVcStoreItems =
                this.dataStore.getItemsWithAttributeLessThanOrEqualValue(
                        userId, "expirationTime", nowPlusSessionTimeout.toString());
        if (!expiredVcStoreItems.isEmpty()) {
            LOGGER.info("Found VCs due to expire within session timeout");
            deleteVcStoreItems(userId);
        }
    }

    public void deleteVcStoreItems(String userId) {
        List<VcStoreItem> vcStoreItems = dataStore.getItems(userId);
        if (!vcStoreItems.isEmpty()) {
            var message =
                    new StringMapMessage()
                            .with("description", "Deleting existing issued VCs")
                            .with(
                                    LogHelper.LogField.NUMBER_OF_VCS.getFieldName(),
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
            String userId, String sub, String vot, List<VcStatusDto> currentVcStatuses)
            throws HttpResponseExceptionWithErrorBody {
        List<VcStoreItem> vcStoreItems = dataStore.getItems(userId);

        List<String> vcJwts =
                vcStoreItems.stream().map(VcStoreItem::getCredential).collect(Collectors.toList());

        String vtm = configService.getSsmParameter(CORE_VTM_CLAIM);

        UserIdentity.UserIdentityBuilder userIdentityBuilder =
                UserIdentity.builder().vcs(vcJwts).sub(sub).vot(vot).vtm(vtm);

        if (vot.equals(VectorOfTrust.P2.toString())) {
            Optional<IdentityClaim> identityClaim =
                    generateIdentityClaim(vcStoreItems, currentVcStatuses);
            identityClaim.ifPresent(userIdentityBuilder::identityClaim);

            Optional<JsonNode> addressClaim = generateAddressClaim(vcStoreItems);
            addressClaim.ifPresent(userIdentityBuilder::addressClaim);

            Optional<JsonNode> passportClaim =
                    generatePassportClaim(vcStoreItems, currentVcStatuses);
            passportClaim.ifPresent(userIdentityBuilder::passportClaim);

            Optional<JsonNode> drivingPermitClaim =
                    generateDrivingPermitClaim(vcStoreItems, currentVcStatuses);
            drivingPermitClaim.ifPresent(userIdentityBuilder::drivingPermitClaim);
        }

        return userIdentityBuilder.build();
    }

    private Optional<IdentityClaim> generateIdentityClaim(
            List<VcStoreItem> vcStoreItems, List<VcStatusDto> currentVcStatuses)
            throws HttpResponseExceptionWithErrorBody {
        for (VcStoreItem item : vcStoreItems) {
            String audienceForClients = getAudienceForClients(item);

            if (EVIDENCE_CRI_TYPES.contains(item.getCredentialIssuer())
                    && isVcSuccessful(currentVcStatuses, audienceForClients)) {
                try {
                    JsonNode nameNode =
                            objectMapper
                                    .readTree(
                                            SignedJWT.parse(item.getCredential())
                                                    .getPayload()
                                                    .toString())
                                    .path(VC_CLAIM)
                                    .path(VC_CREDENTIAL_SUBJECT)
                                    .path(NAME_PROPERTY_NAME);

                    if (nameNode.isMissingNode()) {
                        LOGGER.error("Name property is missing from passport VC");
                        throw new HttpResponseExceptionWithErrorBody(
                                500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM);
                    }

                    JsonNode birthDateNode =
                            objectMapper
                                    .readTree(
                                            SignedJWT.parse(item.getCredential())
                                                    .getPayload()
                                                    .toString())
                                    .path(VC_CLAIM)
                                    .path(VC_CREDENTIAL_SUBJECT)
                                    .path(BIRTH_DATE_PROPERTY_NAME);

                    if (birthDateNode.isMissingNode()) {
                        LOGGER.error("BirthDate property is missing from passport VC");
                        throw new HttpResponseExceptionWithErrorBody(
                                500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM);
                    }

                    List<Name> names =
                            objectMapper.treeToValue(
                                    nameNode,
                                    objectMapper
                                            .getTypeFactory()
                                            .constructCollectionType(List.class, Name.class));
                    List<BirthDate> birthDates =
                            objectMapper.treeToValue(
                                    birthDateNode,
                                    objectMapper
                                            .getTypeFactory()
                                            .constructCollectionType(List.class, BirthDate.class));

                    return Optional.of(new IdentityClaim(names, birthDates));
                } catch (ParseException | JsonProcessingException e) {
                    LOGGER.error("Failed to parse VC JWT because: {}", e.getMessage());
                    throw new HttpResponseExceptionWithErrorBody(
                            500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM);
                }
            }
        }
        LOGGER.warn("Failed to generate identity claim");
        return Optional.empty();
    }

    private Optional<JsonNode> generateAddressClaim(List<VcStoreItem> vcStoreItems)
            throws HttpResponseExceptionWithErrorBody {
        Optional<VcStoreItem> addressCredentialItem =
                vcStoreItems.stream()
                        .filter(
                                credential ->
                                        ADDRESS_CRI_TYPES.contains(
                                                credential.getCredentialIssuer()))
                        .findFirst();

        if (addressCredentialItem.isPresent()) {
            JsonNode addressNode;
            try {
                addressNode =
                        objectMapper
                                .readTree(
                                        SignedJWT.parse(addressCredentialItem.get().getCredential())
                                                .getPayload()
                                                .toString())
                                .path(VC_CLAIM)
                                .path(VC_CREDENTIAL_SUBJECT)
                                .path(ADDRESS_PROPERTY_NAME);
                if (addressNode.isMissingNode()) {
                    LOGGER.error("Address property is missing from address VC");
                    throw new HttpResponseExceptionWithErrorBody(
                            500, ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM);
                }
            } catch (JsonProcessingException | ParseException e) {
                LOGGER.error("Error while parsing Address CRI credential: '{}'", e.getMessage());
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM);
            }
            return Optional.of(addressNode);
        }
        LOGGER.warn("Failed to find Address CRI credential");
        return Optional.empty();
    }

    private Optional<JsonNode> generatePassportClaim(
            List<VcStoreItem> vcStoreItems, List<VcStatusDto> currentVcStatuses)
            throws HttpResponseExceptionWithErrorBody {
        for (VcStoreItem item : vcStoreItems) {
            String audienceForClients = getAudienceForClients(item);
            if (PASSPORT_CRI_TYPES.contains(item.getCredentialIssuer())
                    && isVcSuccessful(currentVcStatuses, audienceForClients)) {
                JsonNode passportNode;
                try {
                    passportNode =
                            objectMapper
                                    .readTree(
                                            SignedJWT.parse(item.getCredential())
                                                    .getPayload()
                                                    .toString())
                                    .path(VC_CLAIM)
                                    .path(VC_CREDENTIAL_SUBJECT)
                                    .path(PASSPORT_PROPERTY_NAME);
                    if (passportNode.isMissingNode()) {
                        StringMapMessage mapMessage =
                                new StringMapMessage()
                                        .with("message", "Passport property is missing from VC")
                                        .with("criIss", item.getCredentialIssuer());
                        LOGGER.warn(mapMessage);

                        return Optional.empty();
                    }
                } catch (JsonProcessingException | ParseException e) {
                    LOGGER.error(
                            "Error while parsing Passport CRI credential: '{}'", e.getMessage());
                    throw new HttpResponseExceptionWithErrorBody(
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_GENERATE_PASSPORT_CLAIM);
                }
                return Optional.of(passportNode);
            }
        }

        LOGGER.warn("Failed to find Passport CRI credential");
        return Optional.empty();
    }

    private Optional<JsonNode> generateDrivingPermitClaim(
            List<VcStoreItem> vcStoreItems, List<VcStatusDto> currentVcStatuses)
            throws HttpResponseExceptionWithErrorBody {
        for (VcStoreItem item : vcStoreItems) {
            String audienceForClients = getAudienceForClients(item);
            if (DRIVING_PERMIT_CRI_TYPES.contains(item.getCredentialIssuer())
                    && isVcSuccessful(currentVcStatuses, audienceForClients)) {
                JsonNode drivingPermitNode;
                try {
                    drivingPermitNode =
                            objectMapper
                                    .readTree(
                                            SignedJWT.parse(item.getCredential())
                                                    .getPayload()
                                                    .toString())
                                    .path(VC_CLAIM)
                                    .path(VC_CREDENTIAL_SUBJECT)
                                    .path(DRIVING_PERMIT_PROPERTY_NAME);

                    if (drivingPermitNode instanceof ArrayNode) {
                        ((ObjectNode) drivingPermitNode.get(0)).remove("fullAddress");
                        ((ObjectNode) drivingPermitNode.get(0)).remove("issueDate");
                    }

                    if (drivingPermitNode.isMissingNode()) {
                        StringMapMessage mapMessage =
                                new StringMapMessage()
                                        .with(
                                                "message",
                                                "Driving Permit property is missing from VC")
                                        .with("criIss", item.getCredentialIssuer());
                        LOGGER.warn(mapMessage);

                        return Optional.empty();
                    }

                    return Optional.of(drivingPermitNode);
                } catch (ParseException | JsonProcessingException e) {
                    LOGGER.error(
                            "Error while parsing Driving Permit CRI credential: '{}'",
                            e.getMessage());
                    throw new HttpResponseExceptionWithErrorBody(
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_GENERATE_DRIVING_PERMIT_CLAIM);
                }
            }
        }
        LOGGER.warn("Failed to find Driving Permit CRI credential");
        return Optional.empty();
    }

    private String getAudienceForClients(VcStoreItem item) {
        return configService.getSsmParameter(
                String.format(
                        "%s/%s/%s",
                        configService.getEnvironmentVariable(
                                CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX),
                        item.getCredentialIssuer(),
                        "audienceForClients"));
    }

    public boolean isVcSuccessful(List<VcStatusDto> currentVcStatuses, String criIss) {
        return currentVcStatuses.stream()
                .filter(vcStatusDto -> vcStatusDto.getCriIss().equals(criIss))
                .findFirst()
                .orElseThrow()
                .getIsSuccessfulVc();
    }
}
