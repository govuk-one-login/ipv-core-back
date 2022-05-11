package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.ParseCredentialIssuerConfigException;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.stream.Collectors;

public class ConfigurationService {

    public static final int LOCALHOST_PORT = 4567;
    private static final String LOCALHOST_URI = "http://localhost:" + LOCALHOST_PORT;
    private static final long DEFAULT_BEARER_TOKEN_TTL_IN_SECS = 3600L;
    private static final String IS_LOCAL = "IS_LOCAL";
    private static final String CLIENT_REDIRECT_URL_SEPARATOR = ",";

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigurationService.class);
    public static final String ENVIRONMENT = "ENVIRONMENT";

    private final SSMProvider ssmProvider;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ConfigurationService(SSMProvider ssmProvider) {
        this.ssmProvider = ssmProvider;
    }

    public ConfigurationService() {
        if (isRunningLocally()) {
            this.ssmProvider =
                    ParamManager.getSsmProvider(
                            SsmClient.builder()
                                    .endpointOverride(URI.create(LOCALHOST_URI))
                                    .httpClient(UrlConnectionHttpClient.create())
                                    .region(Region.EU_WEST_2)
                                    .build());
        } else {
            this.ssmProvider =
                    ParamManager.getSsmProvider(
                            SsmClient.builder()
                                    .httpClient(UrlConnectionHttpClient.create())
                                    .build());
        }
    }

    public SSMProvider getSsmProvider() {
        return ssmProvider;
    }

    public boolean isRunningLocally() {
        return Boolean.parseBoolean(System.getenv(IS_LOCAL));
    }

    public String getAuthCodesTableName() {
        return System.getenv("AUTH_CODES_TABLE_NAME");
    }

    public String getUserIssuedCredentialTableName() {
        return System.getenv("USER_ISSUED_CREDENTIALS_TABLE_NAME");
    }

    public String getAccessTokensTableName() {
        return System.getenv("ACCESS_TOKENS_TABLE_NAME");
    }

    public String getIpvSessionTableName() {
        return System.getenv("IPV_SESSIONS_TABLE_NAME");
    }

    public String getIpvJourneyCriStartUri() {
        return System.getenv("IPV_JOURNEY_CRI_START_URI");
    }

    public String getIpvJourneySessionEnd() {
        return System.getenv("IPV_JOURNEY_SESSION_END_URI");
    }

    public String getSqsAuditEventQueueUrl() {
        return System.getenv("SQS_AUDIT_EVENT_QUEUE_URL");
    }

    public long getBearerAccessTokenTtl() {
        return Optional.ofNullable(System.getenv("BEARER_TOKEN_TTL"))
                .map(Long::valueOf)
                .orElse(DEFAULT_BEARER_TOKEN_TTL_IN_SECS);
    }

    public CredentialIssuerConfig getCredentialIssuer(String credentialIssuerId) {
        Map<String, String> result =
                ssmProvider.getMultiple(
                        String.format(
                                "%s/%s",
                                System.getenv("CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX"),
                                credentialIssuerId));
        return new ObjectMapper().convertValue(result, CredentialIssuerConfig.class);
    }

    public List<CredentialIssuerConfig> getCredentialIssuers()
            throws ParseCredentialIssuerConfigException {
        Map<String, String> params =
                ssmProvider
                        .recursive()
                        .getMultiple(System.getenv("CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX"));

        Map<String, Map<String, Object>> map = new HashMap<>();
        for (Entry<String, String> entry : params.entrySet()) {
            if (map.computeIfAbsent(getCriIdFromParameter(entry), k -> new HashMap<>())
                            .put(getAttributeNameFromParameter(entry), entry.getValue())
                    != null) {
                throw new ParseCredentialIssuerConfigException(
                        String.format(
                                "Duplicate parameter in Parameter Store: %s",
                                getAttributeNameFromParameter(entry)));
            }
        }

        return map.values().stream()
                .map(config -> objectMapper.convertValue(config, CredentialIssuerConfig.class))
                .collect(Collectors.toList());
    }

    private String getAttributeNameFromParameter(Entry<String, String> parameter)
            throws ParseCredentialIssuerConfigException {
        String[] splitKey =
                getSplitKey(
                        parameter,
                        "The attribute name cannot be parsed from the parameter path %s");
        return splitKey[1];
    }

    private String getCriIdFromParameter(Entry<String, String> parameter)
            throws ParseCredentialIssuerConfigException {
        String[] splitKey =
                getSplitKey(
                        parameter,
                        "The credential issuer id cannot be parsed from the parameter path %s");
        return splitKey[0];
    }

    private String[] getSplitKey(Entry<String, String> parameter, String message)
            throws ParseCredentialIssuerConfigException {
        String[] splitKey = parameter.getKey().split("/");
        if (splitKey.length < 2) {
            String errorMessage = String.format(message, parameter.getKey());
            LOGGER.error(errorMessage);
            throw new ParseCredentialIssuerConfigException(errorMessage);
        }
        return splitKey;
    }

    public String getSigningKeyId() {
        return ssmProvider.get(System.getenv("SIGNING_KEY_ID_PARAM"));
    }

    public String getJarKmsEncryptionKeyId() {
        return ssmProvider.get(
                String.format(
                        "/%s/core/self/jarKmsEncryptionPublicKey", System.getenv(ENVIRONMENT)));
    }

    public String getAudienceForClients() {
        return ssmProvider.get(
                String.format("/%s/core/self/audienceForClients", System.getenv(ENVIRONMENT)));
    }

    public List<String> getClientRedirectUrls(String clientId) {
        String redirectUrlStrings =
                ssmProvider.get(
                        String.format(
                                "/%s/core/clients/%s/validRedirectUrls",
                                System.getenv(ENVIRONMENT), clientId));

        return Arrays.asList(redirectUrlStrings.split(CLIENT_REDIRECT_URL_SEPARATOR));
    }

    public String getClientPublicKeyMaterial(String clientId) {

        return ssmProvider.get(
                String.format(
                        "/%s/core/clients/%s/publicKeyMaterialForCoreToVerify",
                        System.getenv(ENVIRONMENT), clientId));
    }

    public String getClientAuthenticationMethod(String clientId) {
        return ssmProvider.get(
                String.format(
                        "/%s/core/clients/%s/authenticationMethod",
                        System.getenv(ENVIRONMENT), clientId));
    }

    public String getClientIssuer(String clientId) {
        return ssmProvider.get(
                String.format("/%s/core/clients/%s/issuer", System.getenv(ENVIRONMENT), clientId));
    }

    public String getClientAudience(String clientId) {
        return ssmProvider.get(
                String.format(
                        "/%s/core/credentialIssuers/%s/audienceForClients",
                        System.getenv(ENVIRONMENT), clientId));
    }

    public String getClientSubject(String clientId) {
        return ssmProvider.get(
                String.format("/%s/core/clients/%s/subject", System.getenv(ENVIRONMENT), clientId));
    }

    public String getMaxAllowedAuthClientTtl() {
        return ssmProvider.get(
                String.format("/%s/core/self/maxAllowedAuthClientTtl", System.getenv(ENVIRONMENT)));
    }

    public String getIpvTokenTtl() {
        return ssmProvider.get(
                String.format("/%s/core/self/jwtTtlSeconds", System.getenv(ENVIRONMENT)));
    }

    public String getCoreFrontCallbackUrl() {
        return ssmProvider.get(
                String.format("/%s/core/self/coreFrontCallbackUrl", System.getenv(ENVIRONMENT)));
    }

    public PublicKey getEncryptionPublicKey(String clientId)
            throws HttpResponseExceptionWithErrorBody {
        try {
            RSAKey rsaKey =
                    RSAKey.parse(
                            ssmProvider.get(
                                    String.format(
                                            "/%s/core/credentialIssuers/%s/jarEncryptionPublicJwk",
                                            System.getenv(ENVIRONMENT), clientId)));
            RSAPublicKeySpec rsaPublicKeySpec =
                    new RSAPublicKeySpec(
                            rsaKey.getModulus().decodeToBigInteger(),
                            rsaKey.getPublicExponent().decodeToBigInteger());
            return KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | ParseException e) {
            throw new HttpResponseExceptionWithErrorBody(
                    500, ErrorResponse.FAILED_TO_GET_ENCRYPTION_PUBLIC_KEY);
        }
    }
}
