package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.http.crt.AwsCrtAsyncHttpClient;
import software.amazon.awssdk.http.crt.AwsCrtHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.DecryptionFailureException;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidParameterException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.awssdk.services.ssm.SsmAsyncClient;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.GetParameterResponse;
import software.amazon.awssdk.services.ssm.model.GetParametersByPathRequest;
import software.amazon.awssdk.services.ssm.model.GetParametersByPathResponse;
import software.amazon.awssdk.services.ssm.model.GetParametersResponse;
import software.amazon.awssdk.services.ssm.model.Parameter;
import software.amazon.awssdk.services.ssm.model.ParameterNotFoundException;
import software.amazon.awssdk.services.ssm.paginators.GetParametersByPathPublisher;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.config.FeatureFlag;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.MitigationRoute;
import uk.gov.di.ipv.core.library.dto.CriConfig;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParseException;
import uk.gov.di.ipv.core.library.exceptions.NoConfigForConnectionException;
import uk.gov.di.ipv.core.library.exceptions.NoCriForIssuerException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import static java.time.temporal.ChronoUnit.MINUTES;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.BEARER_TOKEN_TTL;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CONFIG_SERVICE_CACHE_DURATION_MINUTES;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.ENVIRONMENT;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SIGNING_KEY_ID_PARAM;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CONNECTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_FEATURE_SET;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_PARAMETER_PATH;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_SECRET_ID;

public class ConfigService {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper(new YAMLFactory());
    private static final long DEFAULT_BEARER_TOKEN_TTL_IN_SECS = 3600L;
    private static final int DEFAULT_CACHE_DURATION_MINUTES = 3;
    private static final String CLIENT_REDIRECT_URL_SEPARATOR = ",";
    private static final String API_KEY = "apiKey";
    private static final String CORE_BASE_PATH = "/%s/core/";
    private static final Logger LOGGER = LogManager.getLogger();
    private final SSMProvider ssmProvider;
    private final SecretsProvider secretsProvider;
    private S3Client s3Client;
    private JsonNode coreConfig;
    private SsmClient ssmClient;
    private SsmAsyncClient ssmAsyncClient;
    private HttpClient httpClient;
    private HttpRequest appConfigClientRequest;
    private Instant appConfigLastPull;
    private Map<String, String> configMap;
    private Instant lastRefresh;

    private List<String> featureSet;

    public ConfigService(
            SSMProvider ssmProvider, SecretsProvider secretsProvider, List<String> featureSet) {
        this.ssmProvider = ssmProvider;
        this.secretsProvider = secretsProvider;
        setFeatureSet(featureSet);
    }

    public ConfigService(SSMProvider ssmProvider, SecretsProvider secretsProvider) {
        this(ssmProvider, secretsProvider, null);
    }

    @ExcludeFromGeneratedCoverageReport
    public ConfigService() {
        var cacheDuration =
                getEnvironmentVariable(CONFIG_SERVICE_CACHE_DURATION_MINUTES) == null
                        ? DEFAULT_CACHE_DURATION_MINUTES
                        : Integer.parseInt(
                                getEnvironmentVariable(CONFIG_SERVICE_CACHE_DURATION_MINUTES));

        this.ssmClient = SsmClient.builder().httpClient(AwsCrtHttpClient.create()).build();
        this.ssmAsyncClient =
                SsmAsyncClient.builder()
                        .region(Region.EU_WEST_2)
                        .httpClient(AwsCrtAsyncHttpClient.create())
                        .build();
        this.ssmProvider =
                ParamManager.getSsmProvider(ssmClient).defaultMaxAge(cacheDuration, MINUTES);

        this.secretsProvider =
                ParamManager.getSecretsProvider(
                                SecretsManagerClient.builder()
                                        .httpClient(AwsCrtHttpClient.create())
                                        .build())
                        .defaultMaxAge(cacheDuration, MINUTES);

        this.s3Client =
                S3Client.builder()
                        .region(Region.EU_WEST_2)
                        .httpClient(AwsCrtHttpClient.create())
                        .build();

        httpClient = HttpClient.newHttpClient();
        appConfigClientRequest =
                HttpRequest.newBuilder(
                                URI.create(
                                        "http://localhost:2772/applications/core-back-lambdas/environments/dev-chrisw-lambdas/configurations/PYIC-6854-AppConfigSpike"))
                        .GET()
                        .build();
    }

    public List<String> getFeatureSet() {
        return featureSet;
    }

    public void setFeatureSet(List<String> featureSet) {
        this.featureSet = featureSet;
    }

    public String getEnvironmentVariable(EnvironmentVariable environmentVariable) {
        return System.getenv(environmentVariable.name());
    }

    @Tracing
    public void primeConfigCache(List<ConfigVarWithPathProps> configToFetch) {
        if (configMap == null || lastRefresh.isBefore(Instant.now().minusSeconds(30))) {
            var fullParamNamesList = getFullParamNameList(configToFetch);
            parseFuturesToMap(getParameters(fullParamNamesList));
            lastRefresh = Instant.now();
        }
    }

    @Tracing
    private List<String> getFullParamNameList(List<ConfigVarWithPathProps> configToFetch) {
        return configToFetch.stream()
                .map(
                        param ->
                                resolvePath(
                                        param.configVar().getPath(),
                                        param.pathProps().toArray(new String[0])))
                .toList();
    }

    @Tracing
    private List<CompletableFuture<GetParameterResponse>> getParameters(
            List<String> fullParamNamesList) {
        var completableFutures =
                fullParamNamesList.stream()
                        .map(
                                param ->
                                        ssmAsyncClient.getParameter(
                                                GetParameterRequest.builder().name(param).build()))
                        .toList();
        var allOf = CompletableFuture.allOf(completableFutures.toArray(new CompletableFuture[0]));
        try {
            allOf.get();
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException(e);
        }

        return completableFutures;
    }

    @Tracing
    private void parseFuturesToMap(
            List<CompletableFuture<GetParameterResponse>> completableFutures) {
        configMap = new HashMap<>();
        completableFutures.forEach(
                future -> {
                    try {
                        Parameter parameter = future.get().parameter();
                        configMap.put(parameter.name(), parameter.value());
                    } catch (InterruptedException | ExecutionException e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    @Tracing
    private Map<String, String> responseToMap(GetParametersResponse response) {
        return response.parameters().stream()
                .collect(Collectors.toMap(Parameter::name, Parameter::value));
    }

    @Tracing
    public String getSsmParameter(
            ConfigurationVariable configurationVariable, String... pathProperties) {
//        return configMap.get(resolvePath(configurationVariable.getPath(), pathProperties));
                return spikeAppConfig(configurationVariable, pathProperties);
        //        return spikeGetMultipleAsync(configurationVariable, pathProperties);
        //                return spikeGetMultiple(configurationVariable, pathProperties);
        //        return spikeGetAllFromS3(configurationVariable, pathProperties);
        //        return getSsmParameterWithOverride(configurationVariable.getPath(),
        // pathProperties);
    }

    @Tracing
    private String spikeAppConfig(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        if (coreConfig == null || appConfigLastPull.plusSeconds(30).isBefore(Instant.now())) {
            String fetchedConfig = callAppConfigClient();
            coreConfig = parseAppConfig(fetchedConfig);
        }
        return getValueFromJsonNode(configurationVariable, pathProperties);
    }

    @Tracing
    private JsonNode parseAppConfig(String appConfigYaml) {
        try {
            return OBJECT_MAPPER
                    .readTree(appConfigYaml)
                    .path("managed")
                    .path("ssm")
                    .path("dev-chrisw")
                    .path("core");
        } catch (IOException e) {
            LOGGER.error("Error parsing config yaml", e);
            throw new RuntimeException();
        }
    }

    @Tracing
    private String getValueFromJsonNode(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        var templatedPath =
                String.format(configurationVariable.getPath(), (Object[]) pathProperties);
        var pathParts = new ArrayList<>(Arrays.asList(templatedPath.split("/")));
        var foundNode = coreConfig.path(pathParts.remove(0));
        if (!pathParts.isEmpty()) {
            for (var part : pathParts) {
                foundNode = foundNode.path(part);
            }
        }
        if (foundNode.isMissingNode()) {
            throw new RuntimeException(
                    String.format("Param not found: '%s'", configurationVariable.getPath()));
        }
        return foundNode.asText();
    }

    @Tracing
    private String callAppConfigClient() {
        try {
            var response =
                    httpClient.send(appConfigClientRequest, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() > 299) {
                throw new RuntimeException(
                        String.format(
                                "Non 200 response from app config client: '%d'",
                                response.statusCode()));
            }
            appConfigLastPull = Instant.now();
            return response.body();
        } catch (IOException | InterruptedException e) {
            LOGGER.error("Failed to get all params async", e);
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }

    @Tracing
    private String spikeGetMultiple(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        configMap = configMap == null ? loadAllParamsFromSsmUsingByPath() : configMap;
        return configMap.get(resolvePath(configurationVariable.getPath(), pathProperties));
    }

    @Tracing
    private String spikeGetMultipleAsync(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        if (configMap == null) {
            loadAllParamsFromSsmUsingByPathAndAsync();
        }
        return configMap.get(resolvePath(configurationVariable.getPath(), pathProperties));
    }

    @Tracing
    private void loadAllParamsFromSsmUsingByPathAndAsync() {
        var request =
                GetParametersByPathRequest.builder()
                        .recursive(true)
                        .path("/dev-chrisw/core")
                        .build();
        GetParametersByPathPublisher parametersByPathPaginator1 =
                ssmAsyncClient.getParametersByPathPaginator(request);
        configMap = new HashMap<>();
        CompletableFuture<Void> completableFuture =
                parametersByPathPaginator1
                        .flatMapIterable(GetParametersByPathResponse::parameters)
                        .subscribe(parameter -> configMap.put(parameter.name(), parameter.value()));
        try {
            completableFuture.get();
        } catch (InterruptedException | ExecutionException e) {
            LOGGER.error("Failed to get all params async", e);
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }

    @Tracing
    private Map<String, String> loadAllParamsFromSsmUsingByPath() {
        var request =
                GetParametersByPathRequest.builder()
                        .recursive(true)
                        .path("/dev-chrisw/core")
                        .build();
        var parametersByPathPaginator = ssmClient.getParametersByPathPaginator(request);
        return parametersByPathPaginator.stream()
                .flatMap(page -> page.parameters().stream())
                .collect(Collectors.toMap(Parameter::name, Parameter::value));
    }

    @Tracing
    private String spikeGetAllFromS3(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        coreConfig = coreConfig == null ? getCoreConfig() : coreConfig;
        var templatedPath =
                String.format(configurationVariable.getPath(), (Object[]) pathProperties);
        var pathParts = new ArrayList<>(Arrays.asList(templatedPath.split("/")));
        var foundNode = coreConfig.path(pathParts.remove(0));
        if (!pathParts.isEmpty()) {
            for (var part : pathParts) {
                foundNode = foundNode.path(part);
            }
        }
        if (foundNode.isMissingNode()) {
            throw new RuntimeException(
                    String.format("Param not found: '%s'", configurationVariable.getPath()));
        }
        return foundNode.asText();
    }

    @Tracing
    private JsonNode getCoreConfig() {
        var configYaml = getConfigFromS3();
        JsonNode yamlConfig = parseConfig(configYaml);
        LOGGER.info("Successfully read config yaml");
        return yamlConfig.path("managed").path("ssm").path("dev-chrisw").path("core");
    }

    @Tracing
    private ResponseBytes<GetObjectResponse> getConfigFromS3() {
        var configRequest =
                GetObjectRequest.builder()
                        .bucket("ipv-core-config-mgmt-dev01")
                        .key("configs/params/core.dev-chrisw-params.yaml")
                        .build();
        return s3Client.getObjectAsBytes(configRequest);
    }

    @Tracing
    private JsonNode parseConfig(ResponseBytes<GetObjectResponse> configBytes) {
        try {
            return OBJECT_MAPPER.readTree(configBytes.asByteArray());
        } catch (IOException e) {
            LOGGER.error("Error parsing config yaml", e);
            throw new RuntimeException();
        }
    }

    @Tracing
    private String getSsmParameterWithOverride(String templatePath, String... pathProperties) {
        if (this.featureSet != null) {
            for (String fs : this.featureSet) {
                final Path featureSetPath =
                        Path.of(resolveFeatureSetPath(fs, templatePath, pathProperties));
                final String terminal = featureSetPath.getFileName().toString();
                final String basePath = featureSetPath.getParent().toString();
                final Map<String, String> overrides = ssmProvider.getMultiple(basePath);
                if (overrides.containsKey(terminal)) {
                    return overrides.get(terminal);
                } else {
                    LOGGER.debug(
                            (new StringMapMessage())
                                    .with(
                                            LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                            "Parameter not present for featureSet")
                                    .with(LOG_PARAMETER_PATH.getFieldName(), templatePath)
                                    .with(LOG_FEATURE_SET.getFieldName(), fs));
                }
            }
        }
        return ssmProvider.get(resolvePath(templatePath, pathProperties));
    }

    @Tracing
    private String resolveBasePath() {
        return String.format(CORE_BASE_PATH, getEnvironmentVariable(ENVIRONMENT));
    }

    @Tracing
    protected String resolvePath(String path, String... pathProperties) {
        return resolveBasePath() + String.format(path, (Object[]) pathProperties);
    }

    @Tracing
    private String resolveFeatureSetPath(String featureSet, String path, String... pathProperties) {
        return resolveBasePath()
                + String.format("features/%s/", featureSet)
                + String.format(path, (Object[]) pathProperties);
    }

    public long getBearerAccessTokenTtl() {
        return Optional.ofNullable(getEnvironmentVariable(BEARER_TOKEN_TTL))
                .map(Long::valueOf)
                .orElse(DEFAULT_BEARER_TOKEN_TTL_IN_SECS);
    }

    public String getSigningKeyId() {
        return ssmProvider.get(getEnvironmentVariable(SIGNING_KEY_ID_PARAM));
    }

    public List<String> getClientRedirectUrls(String clientId) {
        String redirectUrlStrings =
                getSsmParameter(ConfigurationVariable.CLIENT_VALID_REDIRECT_URLS, clientId);
        return Arrays.asList(redirectUrlStrings.split(CLIENT_REDIRECT_URL_SEPARATOR));
    }

    public String getCriPrivateApiKeyForActiveConnection(String criId) {
        return getApiKeyFromSecretManager(criId, getActiveConnection(criId));
    }

    public String getAppApiKey(String appId) {
        return getApiKeyFromSecretManager(appId);
    }

    public String getCriPrivateApiKey(CriOAuthSessionItem criOAuthSessionItem) {
        return getApiKeyFromSecretManager(
                criOAuthSessionItem.getCriId(), criOAuthSessionItem.getConnection());
    }

    public String getCriOAuthClientSecret(CriOAuthSessionItem criOAuthSessionItem) {
        return getOAuthClientSecretFromSecretManager(
                criOAuthSessionItem.getCriId(), criOAuthSessionItem.getConnection());
    }

    public OauthCriConfig getOauthCriActiveConnectionConfig(String credentialIssuerId) {
        return getOauthCriConfigForConnection(
                getActiveConnection(credentialIssuerId), credentialIssuerId);
    }

    public OauthCriConfig getOauthCriConfig(CriOAuthSessionItem criOAuthSessionItem) {
        return getOauthCriConfigForConnection(
                criOAuthSessionItem.getConnection(), criOAuthSessionItem.getCriId());
    }

    public OauthCriConfig getOauthCriConfigForConnection(String connection, String criId) {
        return getCriConfigForType(connection, criId, OauthCriConfig.class);
    }

    public RestCriConfig getRestCriConfig(String criId) {
        return getCriConfigForType(getActiveConnection(criId), criId, RestCriConfig.class);
    }

    public CriConfig getCriConfig(String criId) {
        return getCriConfigForType(getActiveConnection(criId), criId, CriConfig.class);
    }

    public String getActiveConnection(String credentialIssuerId) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/activeConnection";
        return getSsmParameterWithOverride(pathTemplate, credentialIssuerId);
    }

    public String getComponentId(String credentialIssuerId) {
        var criConfig = getOauthCriActiveConnectionConfig(credentialIssuerId);
        return criConfig.getComponentId();
    }

    public String getAllowedSharedAttributes(String credentialIssuerId) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/allowedSharedAttributes";
        return getSsmParameterWithOverride(pathTemplate, credentialIssuerId);
    }

    public boolean isEnabled(String credentialIssuerId) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/enabled";
        return Boolean.parseBoolean(getSsmParameterWithOverride(pathTemplate, credentialIssuerId));
    }

    public Map<String, ContraIndicatorConfig> getContraIndicatorConfigMap() {
        try {
            String secretValue = getCoreSecretValue(ConfigurationVariable.CI_CONFIG);
            List<ContraIndicatorConfig> configList =
                    OBJECT_MAPPER.readValue(secretValue, new TypeReference<>() {});
            Map<String, ContraIndicatorConfig> configMap = new HashMap<>();
            for (ContraIndicatorConfig config : configList) {
                configMap.put(config.getCi(), config);
            }
            return configMap;
        } catch (JsonProcessingException e) {
            LOGGER.error(LogHelper.buildLogMessage("Failed to parse contra-indicator config"));
            return Collections.emptyMap();
        }
    }

    public Map<String, List<MitigationRoute>> getCimitConfig() throws ConfigException {
        final String cimitConfig = getSsmParameter(ConfigurationVariable.CIMIT_CONFIG);
        try {
            return OBJECT_MAPPER.readValue(
                    cimitConfig, new TypeReference<HashMap<String, List<MitigationRoute>>>() {});
        } catch (JsonProcessingException e) {
            throw new ConfigException("Failed to parse CIMit configuration");
        }
    }

    public boolean enabled(FeatureFlag featureFlag) {
        return Boolean.parseBoolean(
                getSsmParameter(ConfigurationVariable.FEATURE_FLAGS, featureFlag.getName()));
    }

    public boolean enabled(String featureFlagValue) {
        return Boolean.parseBoolean(
                getSsmParameter(ConfigurationVariable.FEATURE_FLAGS, featureFlagValue));
    }

    public String getCoreSecretValue(ConfigurationVariable secretName) {
        String secretId = resolveBasePath() + secretName.getPath();
        return getSecretValue(secretId);
    }

    private String getSecretValue(String secretId) {
        try {
            return secretsProvider.get(secretId);
        } catch (DecryptionFailureException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Secrets manager failed to decrypt the protected secret using the configured KMS key",
                            e));
        } catch (InternalServiceErrorException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Internal server error occurred with Secrets manager", e));
        } catch (InvalidParameterException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            String.format(
                                    "An invalid value was provided for the param value: %s",
                                    secretId),
                            e));
        } catch (InvalidRequestException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Parameter value is not valid for the current state of the resource",
                            e));
        } catch (ResourceNotFoundException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                                    "Failed to find the resource within Secrets manager.", e)
                            .with(LOG_SECRET_ID.getFieldName(), secretId));
        }
        return null;
    }

    private String getApiKeyFromSecretManager(String criId, String connection) {
        String secretId =
                String.format(
                        "/%s/credential-issuers/%s/connections/%s/api-key",
                        getEnvironmentVariable(ENVIRONMENT), criId, connection);
        return getSecretValue(criId, connection, secretId);
    }

    private String getApiKeyFromSecretManager(String appId) {
        String secretId = resolvePath("%s/api-key", appId);
        return getSecretValue(appId, null, secretId);
    }

    private String getSecretValue(String criId, String connection, String secretId) {
        try {
            String secretValue = getSecretValue(secretId);

            if (secretValue != null) {
                Map<String, String> secret =
                        OBJECT_MAPPER.readValue(secretValue, new TypeReference<>() {});
                return secret.get(API_KEY);
            }
            LOGGER.warn(
                    (new StringMapMessage())
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "API key not found")
                            .with(LOG_CRI_ID.getFieldName(), criId)
                            .with(LOG_CONNECTION.getFieldName(), connection));
            return null;
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    "Failed to parse the api key secret from secrets manager for client: {}",
                    criId);
            return null;
        }
    }

    private String getOAuthClientSecretFromSecretManager(String criId, String connection) {
        String secretId =
                String.format(
                        "/%s/credential-issuers/%s/connections/%s/oauth-client-secret",
                        getEnvironmentVariable(ENVIRONMENT), criId, connection);

        String secretValue = getSecretValue(secretId);

        if (secretValue == null) {
            LOGGER.warn(
                    (new StringMapMessage())
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "OAuth secret value not found")
                            .with(LOG_CRI_ID.getFieldName(), criId)
                            .with(LOG_CONNECTION.getFieldName(), connection));
        }

        return secretValue;
    }

    private <T> T getCriConfigForType(String connection, String criId, Class<T> configType) {

        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/connections/%s";
        try {
            String parameter = ssmProvider.get(resolvePath(pathTemplate, criId, connection));
            return OBJECT_MAPPER.readValue(parameter, configType);
        } catch (ParameterNotFoundException e) {
            throw new NoConfigForConnectionException(
                    String.format(
                            "No config found for connection: '%s' and criId: '%s'",
                            connection, criId));
        } catch (JsonProcessingException e) {
            throw new ConfigParseException(
                    String.format(
                            "Failed to parse credential issuer configuration at parameter path '%s' because: '%s'",
                            pathTemplate, e));
        }
    }

    private List<String> getCriComponentIds(Cri cri) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/connections";
        var criId = cri.getId();
        var result = new ArrayList<String>();
        try {
            var parameters = ssmProvider.getMultiple(resolvePath(pathTemplate, criId));
            for (var parameter : parameters.values()) {
                var criConfig = OBJECT_MAPPER.readValue(parameter, CriConfig.class);

                result.add(criConfig.getComponentId());
            }
            return result;
        } catch (ParameterNotFoundException e) {
            throw new NoConfigForConnectionException(
                    String.format("No config found for criId: '%s'", criId));
        } catch (JsonProcessingException e) {
            throw new ConfigParseException(
                    String.format(
                            "Failed to parse credential issuer configuration at parameter path '%s' because: '%s'",
                            pathTemplate, e));
        }
    }

    public Cri getCriByIssuer(String issuer) throws NoCriForIssuerException {
        for (var cri : Cri.values()) {
            for (var componentId : getCriComponentIds(cri)) {
                if (issuer.equals(componentId)) {
                    return cri;
                }
            }
        }
        throw new NoCriForIssuerException(String.format("No cri found for issuer: '%s'", issuer));
    }
}
