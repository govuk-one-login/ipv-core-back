package uk.gov.di.ipv.core.library.service;

import com.google.gson.Gson;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.DebugCredentialAttributes;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.domain.UserIssuedDebugCredential;
import uk.gov.di.ipv.core.library.domain.VectorOfTrust;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;

import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;

public class UserIdentityService {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserIdentityService.class);
    private static final String PASSPORT_CRI_TYPE = "ukPassport";
    private static final String FRAUD_CRI_TYPE = "fraud";
    private static final String KBV_CRI_TYPE = "kbv";
    private static final String GPG_45_VALIDITY_PROPERTY_NAME = "validity";
    private static final String GPG_45_FRAUD_PROPERTY_NAME = "fraud";
    private static final String GPG_45_VERIFICATION_PROPERTY_NAME = "verification";
    private static final int GPG_45_M1A_VALIDITY_SCORE = 2;
    private static final int GPG_45_M1A_FRAUD_SCORE = 1;
    private static final int GPG_45_M1A_VERIFICATION_SCORE = 2;

    private final ConfigurationService configurationService;
    private final DataStore<UserIssuedCredentialsItem> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public UserIdentityService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        boolean isRunningLocally = this.configurationService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getUserIssuedCredentialTableName(),
                        UserIssuedCredentialsItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally);
    }

    public UserIdentityService(
            ConfigurationService configurationService,
            DataStore<UserIssuedCredentialsItem> dataStore) {
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public UserIdentity getUserIssuedCredentials(String ipvSessionId) {
        List<UserIssuedCredentialsItem> credentialIssuerItems = dataStore.getItems(ipvSessionId);

        List<String> vcJwts =
                credentialIssuerItems.stream()
                        .map(UserIssuedCredentialsItem::getCredential)
                        .collect(Collectors.toList());

        String vot = generateVectorOfTrustClaim(credentialIssuerItems);

        String vtm = configurationService.getCoreVtmClaim();

        return new UserIdentity.Builder().setVcs(vcJwts).setVot(vot).setVtm(vtm).build();
    }

    public Map<String, String> getUserIssuedDebugCredentials(String ipvSessionId) {
        List<UserIssuedCredentialsItem> credentialIssuerItems = dataStore.getItems(ipvSessionId);
        Map<String, String> userIssuedDebugCredentials = new HashMap<>();

        Gson gson = new Gson();
        credentialIssuerItems.forEach(
                criItem -> {
                    DebugCredentialAttributes attributes =
                            new DebugCredentialAttributes(
                                    criItem.getIpvSessionId(), criItem.getDateCreated().toString());
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

                if (item.getCredentialIssuer().equals(PASSPORT_CRI_TYPE)) {
                    validPassport =
                            isValidScore(
                                    evidenceArray,
                                    GPG_45_VALIDITY_PROPERTY_NAME,
                                    GPG_45_M1A_VALIDITY_SCORE);
                }

                if (item.getCredentialIssuer().equals(FRAUD_CRI_TYPE)) {
                    validFraud =
                            isValidScore(
                                    evidenceArray,
                                    GPG_45_FRAUD_PROPERTY_NAME,
                                    GPG_45_M1A_FRAUD_SCORE);
                }

                if (item.getCredentialIssuer().equals(KBV_CRI_TYPE)) {
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
