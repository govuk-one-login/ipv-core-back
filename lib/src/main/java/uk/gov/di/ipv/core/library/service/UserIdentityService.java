package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.DebugCredentialAttributes;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.domain.UserIssuedDebugCredential;
import uk.gov.di.ipv.core.library.domain.VectorOfTrust;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;

import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_VTM_CLAIM;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class UserIdentityService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String NAME_PROPERTY_NAME = "name";
    private static final String BIRTH_DATE_PROPERTY_NAME = "birthDate";
    private static final String ADDRESS_PROPERTY_NAME = "address";
    private static final String PASSPORT_PROPERTY_NAME = "passport";
    private static final List<String> ADDRESS_CRI_TYPES =
            List.of(ADDRESS_PROPERTY_NAME, "stubAddress");
    private static final List<String> PASSPORT_CRI_TYPES = List.of("ukPassport", "stubUkPassport");
    private static final List<String> EVIDENCE_CRI_TYPES =
            List.of("ukPassport", "stubUkPassport", "dcmaw", "stubDcmaw");
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final ConfigurationService configurationService;
    private final DataStore<UserIssuedCredentialsItem> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public UserIdentityService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        boolean isRunningLocally = this.configurationService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getEnvironmentVariable(
                                USER_ISSUED_CREDENTIALS_TABLE_NAME),
                        UserIssuedCredentialsItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configurationService);
    }

    public UserIdentityService(
            ConfigurationService configurationService,
            DataStore<UserIssuedCredentialsItem> dataStore) {
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public List<String> getUserIssuedCredentials(String userId) {
        List<UserIssuedCredentialsItem> credentialIssuerItems = dataStore.getItems(userId);

        return credentialIssuerItems.stream()
                .map(UserIssuedCredentialsItem::getCredential)
                .collect(Collectors.toList());
    }

    public void deleteUserIssuedCredentials(String userId) {
        List<UserIssuedCredentialsItem> credentialIssuerItems = dataStore.getItems(userId);
        if (!credentialIssuerItems.isEmpty()) {
            LogHelper.logInfoMessageWithFieldAndValue(
                    "Deleting existing issued VCs",
                    LogHelper.LogField.NUMBER_OF_VCS,
                    String.valueOf(credentialIssuerItems.size()));
        }
        for (UserIssuedCredentialsItem item : credentialIssuerItems) {
            dataStore.delete(item.getUserId(), item.getCredentialIssuer());
        }
    }

    public UserIssuedCredentialsItem getUserIssuedCredential(String userId, String criId) {
        return dataStore.getItem(userId, criId);
    }

    public UserIdentity generateUserIdentity(String userId, String sub, String vot)
            throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> credentialIssuerItems = dataStore.getItems(userId);

        List<String> vcJwts =
                credentialIssuerItems.stream()
                        .map(UserIssuedCredentialsItem::getCredential)
                        .collect(Collectors.toList());

        String vtm = configurationService.getSsmParameter(CORE_VTM_CLAIM);

        UserIdentity.Builder userIdentityBuilder =
                new UserIdentity.Builder().setVcs(vcJwts).setSub(sub).setVot(vot).setVtm(vtm);

        if (vot.equals(VectorOfTrust.P2.toString())) {
            Optional<IdentityClaim> identityClaim = generateIdentityClaim(credentialIssuerItems);
            identityClaim.ifPresent(userIdentityBuilder::setIdentityClaim);

            Optional<JsonNode> addressClaim = generateAddressClaim(credentialIssuerItems);
            addressClaim.ifPresent(userIdentityBuilder::setAddressClaim);

            Optional<JsonNode> passportClaim = generatePassportClaim(credentialIssuerItems);
            passportClaim.ifPresent(userIdentityBuilder::setPassportClaim);
        }

        return userIdentityBuilder.build();
    }

    public Map<String, String> getUserIssuedDebugCredentials(String userId) {
        List<UserIssuedCredentialsItem> credentialIssuerItems = dataStore.getItems(userId);
        Map<String, String> userIssuedDebugCredentials = new HashMap<>();
        Gson gson = new Gson();

        credentialIssuerItems.forEach(
                criItem -> {
                    DebugCredentialAttributes attributes =
                            new DebugCredentialAttributes(
                                    criItem.getUserId(), criItem.getDateCreated().toString());
                    UserIssuedDebugCredential debugCredential =
                            new UserIssuedDebugCredential(attributes);

                    try {
                        JWTClaimsSet jwtClaimsSet =
                                SignedJWT.parse(criItem.getCredential()).getJWTClaimsSet();
                        JSONObject vcClaim = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
                        if (vcClaim == null || isNotPopulatedJsonArray(vcClaim.get(VC_EVIDENCE))) {
                            LOGGER.error("Evidence not found in verifiable credential");
                        } else {
                            JSONArray evidenceArray = ((JSONArray) vcClaim.get(VC_EVIDENCE));
                            debugCredential.setEvidence((Map<String, Object>) evidenceArray.get(0));
                        }
                    } catch (ParseException e) {
                        LOGGER.error("Failed to parse credential JSON for the debug page");
                    }

                    String debugCredentialJson = gson.toJson(debugCredential);

                    userIssuedDebugCredentials.put(
                            criItem.getCredentialIssuer(), debugCredentialJson);
                });

        return userIssuedDebugCredentials;
    }

    private Optional<IdentityClaim> generateIdentityClaim(
            List<UserIssuedCredentialsItem> credentialIssuerItems)
            throws HttpResponseExceptionWithErrorBody {
        for (UserIssuedCredentialsItem item : credentialIssuerItems) {
            if (EVIDENCE_CRI_TYPES.contains(item.getCredentialIssuer())) {
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
        LOGGER.info("Failed to generate identity claim");
        return Optional.empty();
    }

    private Optional<JsonNode> generateAddressClaim(
            List<UserIssuedCredentialsItem> credentialIssuerItems)
            throws HttpResponseExceptionWithErrorBody {
        Optional<UserIssuedCredentialsItem> addressCredentialItem =
                credentialIssuerItems.stream()
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
        LOGGER.error("Failed to find Address CRI credential");
        return Optional.empty();
    }

    private Optional<JsonNode> generatePassportClaim(
            List<UserIssuedCredentialsItem> credentialIssuerItems)
            throws HttpResponseExceptionWithErrorBody {
        Optional<UserIssuedCredentialsItem> passportCredentialItem =
                credentialIssuerItems.stream()
                        .filter(
                                credential ->
                                        PASSPORT_CRI_TYPES.contains(
                                                credential.getCredentialIssuer()))
                        .findFirst();

        if (passportCredentialItem.isPresent()) {
            JsonNode passportNode;
            try {
                passportNode =
                        objectMapper
                                .readTree(
                                        SignedJWT.parse(
                                                        passportCredentialItem
                                                                .get()
                                                                .getCredential())
                                                .getPayload()
                                                .toString())
                                .path(VC_CLAIM)
                                .path(VC_CREDENTIAL_SUBJECT)
                                .path(PASSPORT_PROPERTY_NAME);
                if (passportNode.isMissingNode()) {
                    LOGGER.error("Passport property is missing from passport VC");
                    throw new HttpResponseExceptionWithErrorBody(
                            500, ErrorResponse.FAILED_TO_GENERATE_PASSPORT_CLAIM);
                }
            } catch (JsonProcessingException | ParseException e) {
                LOGGER.error("Error while parsing Passport CRI credential: '{}'", e.getMessage());
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_GENERATE_PASSPORT_CLAIM);
            }
            return Optional.of(passportNode);
        }

        LOGGER.error("Failed to find Passport CRI credential");
        return Optional.empty();
    }

    private boolean isNotPopulatedJsonArray(Object input) {
        return !(input instanceof JSONArray)
                || ((JSONArray) input).isEmpty()
                || !(((JSONArray) input).get(0) instanceof JSONObject);
    }

    public List<String> getUserIssuedCredentialIssuers(String userId) {
        List<UserIssuedCredentialsItem> credentialIssuerItems = dataStore.getItems(userId);

        return credentialIssuerItems.stream()
                .map(UserIssuedCredentialsItem::getCredentialIssuer)
                .collect(Collectors.toList());
    }
}
