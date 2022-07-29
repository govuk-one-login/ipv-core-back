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
    private static final String GPG_45_VALIDITY_PROPERTY_NAME = "validityScore";
    private static final String GPG_45_FRAUD_PROPERTY_NAME = "identityFraudScore";
    private static final String GPG_45_VERIFICATION_PROPERTY_NAME = "verificationScore";
    private static final int GPG_45_M1A_VALIDITY_SCORE = 2;
    private static final int GPG_45_M1A_FRAUD_SCORE = 1;
    private static final int GPG_45_M1A_VERIFICATION_SCORE = 2;
    private static final List<String> ADDRESS_CRI_TYPES =
            List.of(ADDRESS_PROPERTY_NAME, "stubAddress");
    private static final List<String> PASSPORT_CRI_TYPES = List.of("ukPassport", "stubUkPassport");
    private static final List<String> FRAUD_CRI_TYPES = List.of("fraud", "stubFraud");
    private static final List<String> KBV_CRI_TYPES = List.of("kbv", "stubKbv");
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

    public UserIssuedCredentialsItem getUserIssuedCredential(String userId, String criId) {
        return dataStore.getItem(userId, criId);
    }

    public UserIdentity generateUserIdentity(String userId, String sub)
            throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> credentialIssuerItems = dataStore.getItems(userId);

        List<String> vcJwts =
                credentialIssuerItems.stream()
                        .map(UserIssuedCredentialsItem::getCredential)
                        .collect(Collectors.toList());

        String vot = generateVectorOfTrustClaim(credentialIssuerItems);

        String vtm = configurationService.getSsmParameter(CORE_VTM_CLAIM);

        UserIdentity.Builder userIdentityBuilder =
                new UserIdentity.Builder().setVcs(vcJwts).setSub(sub).setVot(vot).setVtm(vtm);

        if (vot.equals(VectorOfTrust.P2.toString())) {
            userIdentityBuilder.setIdentityClaim(generateIdentityClaim(credentialIssuerItems));
            userIdentityBuilder.setAddressClaim(generateAddressClaim(credentialIssuerItems));
            userIdentityBuilder.setPassportClaim(generatePassportClaim(credentialIssuerItems));
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

    private String generateVectorOfTrustClaim(
            List<UserIssuedCredentialsItem> credentialIssuerItems) {
        Optional<Boolean> validPassport = Optional.empty();
        Optional<Boolean> validFraud = Optional.empty();
        Optional<Boolean> validKbv = Optional.empty();

        for (UserIssuedCredentialsItem item : credentialIssuerItems) {
            try {
                JWTClaimsSet jwtClaimsSet = SignedJWT.parse(item.getCredential()).getJWTClaimsSet();
                JSONObject vcClaim = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
                JSONArray evidenceArray = ((JSONArray) vcClaim.get(VC_EVIDENCE));

                if (PASSPORT_CRI_TYPES.contains(item.getCredentialIssuer())) {
                    validPassport =
                            isValidScore(
                                    evidenceArray,
                                    GPG_45_VALIDITY_PROPERTY_NAME,
                                    GPG_45_M1A_VALIDITY_SCORE);
                }

                if (FRAUD_CRI_TYPES.contains(item.getCredentialIssuer())) {
                    validFraud =
                            isValidScore(
                                    evidenceArray,
                                    GPG_45_FRAUD_PROPERTY_NAME,
                                    GPG_45_M1A_FRAUD_SCORE);
                }

                if (KBV_CRI_TYPES.contains(item.getCredentialIssuer())) {
                    validKbv =
                            isValidScore(
                                    evidenceArray,
                                    GPG_45_VERIFICATION_PROPERTY_NAME,
                                    GPG_45_M1A_VERIFICATION_SCORE);
                }
            } catch (ParseException e) {
                LOGGER.warn("Failed to parse VC JWT");
            }
        }

        return getVectorOfTrustValue(validPassport, validFraud, validKbv);
    }

    private IdentityClaim generateIdentityClaim(
            List<UserIssuedCredentialsItem> credentialIssuerItems)
            throws HttpResponseExceptionWithErrorBody {
        for (UserIssuedCredentialsItem item : credentialIssuerItems) {
            if (PASSPORT_CRI_TYPES.contains(item.getCredentialIssuer())) {
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

                    return new IdentityClaim(names, birthDates);
                } catch (ParseException | JsonProcessingException e) {
                    LOGGER.error("Failed to parse VC JWT because: {}", e.getMessage());
                    throw new HttpResponseExceptionWithErrorBody(
                            500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM);
                }
            }
        }
        throw new HttpResponseExceptionWithErrorBody(
                500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM);
    }

    private JsonNode generateAddressClaim(List<UserIssuedCredentialsItem> credentialIssuerItems)
            throws HttpResponseExceptionWithErrorBody {
        UserIssuedCredentialsItem addressCredentialItem =
                credentialIssuerItems.stream()
                        .filter(
                                credential ->
                                        ADDRESS_CRI_TYPES.contains(
                                                credential.getCredentialIssuer()))
                        .findFirst()
                        .orElseThrow(
                                () -> {
                                    LOGGER.error("Failed to find Address CRI credential");
                                    return new HttpResponseExceptionWithErrorBody(
                                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                                            ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM);
                                });

        JsonNode addressNode;
        try {
            addressNode =
                    objectMapper
                            .readTree(
                                    SignedJWT.parse(addressCredentialItem.getCredential())
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

        return addressNode;
    }

    private JsonNode generatePassportClaim(List<UserIssuedCredentialsItem> credentialIssuerItems)
            throws HttpResponseExceptionWithErrorBody {
        UserIssuedCredentialsItem passportCredentialItem =
                credentialIssuerItems.stream()
                        .filter(
                                credential ->
                                        PASSPORT_CRI_TYPES.contains(
                                                credential.getCredentialIssuer()))
                        .findFirst()
                        .orElseThrow(
                                () -> {
                                    LOGGER.error("Failed to find Passport CRI credential");
                                    return new HttpResponseExceptionWithErrorBody(
                                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                                            ErrorResponse.FAILED_TO_GENERATE_PASSPORT_CLAIM);
                                });

        JsonNode passportNode;
        try {
            passportNode =
                    objectMapper
                            .readTree(
                                    SignedJWT.parse(passportCredentialItem.getCredential())
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
        return passportNode;
    }

    private Optional<Boolean> isValidScore(
            JSONArray evidenceArray, String property, int scoreValue) {
        Long gpg45ScoreValue = ((Map<String, Long>) evidenceArray.get(0)).get(property);
        if (gpg45ScoreValue != null) {
            return Optional.of(gpg45ScoreValue.intValue() >= scoreValue);
        }
        return Optional.empty();
    }

    private String getVectorOfTrustValue(
            Optional<Boolean> validPassport,
            Optional<Boolean> validFraud,
            Optional<Boolean> validKbv) {
        if (validPassport.isPresent()
                && Boolean.TRUE.equals(validPassport.get())
                && validFraud.isPresent()
                && Boolean.TRUE.equals(validFraud.get())
                && validKbv.isPresent()
                && Boolean.TRUE.equals(validKbv.get())) {
            return VectorOfTrust.P2.toString();
        } else {
            return VectorOfTrust.P0.toString();
        }
    }

    private boolean isNotPopulatedJsonArray(Object input) {
        return !(input instanceof JSONArray)
                || ((JSONArray) input).isEmpty()
                || !(((JSONArray) input).get(0) instanceof JSONObject);
    }
}
