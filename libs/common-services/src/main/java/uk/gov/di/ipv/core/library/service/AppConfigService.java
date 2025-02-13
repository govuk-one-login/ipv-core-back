package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.Setter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.appconfigdata.AppConfigDataClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.DecryptionFailureException;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidParameterException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.lambda.powertools.parameters.AppConfigProvider;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static java.time.temporal.ChronoUnit.MINUTES;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CONFIG_SERVICE_CACHE_DURATION_MINUTES;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.ENVIRONMENT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_SECRET_ID;

public class AppConfigService extends YamlParametersConfigService {

    private static final Logger LOGGER = LogManager.getLogger(AppConfigService.class);
    private static final int DEFAULT_CACHE_DURATION_MINUTES = 3;
    private static final String CORE_BASE_PATH = "/%s/core/";
    private static final String CORE = "core";

    @Getter @Setter private List<String> featureSet;
    private final String applicationId = getEnvironmentVariable(EnvironmentVariable.APP_CONFIG_ID);
    private final String environmentId =
            getEnvironmentVariable(EnvironmentVariable.APP_CONFIG_ENVIRONMENT_ID);
    private final String profileId =
            getEnvironmentVariable(EnvironmentVariable.APP_CONFIG_PROFILE_ID);
    private String paramsRawHash;
    private AppConfigProvider appConfigProvider;
    private final SecretsProvider secretsProvider;

    @ExcludeFromGeneratedCoverageReport
    public AppConfigService() {
        var cacheDuration =
                getIntegerEnvironmentVariable(
                        CONFIG_SERVICE_CACHE_DURATION_MINUTES, DEFAULT_CACHE_DURATION_MINUTES);

        appConfigProvider =
                (AppConfigProvider)
                        ParamManager.getAppConfigProvider(
                                        AppConfigDataClient.builder()
                                                .httpClient(UrlConnectionHttpClient.create())
                                                .build(),
                                        environmentId,
                                        applicationId)
                                .withMaxAge(cacheDuration, MINUTES);

        // Initialise parameters value
        parseParametersIfNew(appConfigProvider.get(profileId));

        ObjectMapper mapper = new ObjectMapper();
        try {
            LOGGER.error(String.format("WHAT %s", mapper.writeValueAsString(parameters)));
        } catch (Exception e) {
            LOGGER.error(String.format("WHAT %s", parameters));
        }

        secretsProvider =
                ParamManager.getSecretsProvider(
                                SecretsManagerClient.builder()
                                        .httpClient(UrlConnectionHttpClient.create())
                                        .build())
                        .defaultMaxAge(cacheDuration, MINUTES);
    }

    @ExcludeFromGeneratedCoverageReport
    public AppConfigService(AppConfigProvider appConfigProvider, SecretsProvider secretsProvider) {
        this.appConfigProvider = appConfigProvider;
        this.secretsProvider = secretsProvider;
    }

    @Override
    public String getParameter(String path) {
        // Temporary. Delete on next AWS Powertools release:
        // https://github.com/aws-powertools/powertools-lambda-java/issues/1672
        appConfigProvider =
                ParamManager.getAppConfigProvider(
                        AppConfigDataClient.builder()
                                .httpClient(UrlConnectionHttpClient.create())
                                .build(),
                        environmentId,
                        applicationId);

        LOGGER.error(String.format("getParameter path: %s", path));
        var a = appConfigProvider.get(profileId);
        parseParametersIfNew(a);

        LOGGER.error(String.format("getParameter a: %s", a));
        var b = this.getParameterFromStoredValue(path);

        LOGGER.error(String.format("getParameter b: %s", b));
        return b;
    }

    @Override
    public Map<String, String> getParametersByPrefix(String path) {
        // Temporary. Delete on next AWS Powertools release:
        // https://github.com/aws-powertools/powertools-lambda-java/issues/1672
        appConfigProvider =
                ParamManager.getAppConfigProvider(
                        AppConfigDataClient.builder()
                                .httpClient(UrlConnectionHttpClient.create())
                                .build(),
                        environmentId,
                        applicationId);
        parseParametersIfNew(appConfigProvider.get(profileId));
        return this.getParametersFromStoredValueByPrefix(path);
    }

    private void parseParametersIfNew(String paramsRaw) {
        var retrievedParamsHash = getParamsRawHash(paramsRaw);
        if (!Objects.equals(paramsRawHash, retrievedParamsHash)) {
            initializeConfig(paramsRaw);
            paramsRawHash = retrievedParamsHash;
        }
    }

    private static String getParamsRawHash(String appConfigYaml) {
        try {
            var messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.digest(appConfigYaml.getBytes());
            return new String(messageDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private void initializeConfig(String paramsRaw) {
        try {
            var paramsYaml = YAML_OBJECT_MAPPER.readTree(paramsRaw).get(CORE);
            addJsonConfig(parameters, paramsYaml);
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not load parameter yaml", e);
        }
    }

    @Override
    public String getSecret(String path) {
        try {
            return secretsProvider.get(resolveSecretPath(path));
        } catch (DecryptionFailureException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Secrets manager failed to decrypt the protected secret using the configured KMS key",
                            e));
        } catch (InternalServiceErrorException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Internal server error occurred with Secrets manager", e));
        } catch (InvalidRequestException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Parameter value is not valid for the current state of the resource",
                            e));
        } catch (InvalidParameterException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            String.format(
                                    "An invalid value was provided for the param value: %s", path),
                            e));
        } catch (ResourceNotFoundException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                                    "Failed to find the resource within Secrets manager.", e)
                            .with(LOG_SECRET_ID.getFieldName(), path));
        }
        return null;
    }

    private String resolveSecretPath(String path) {
        return String.format(CORE_BASE_PATH, getEnvironmentVariable(ENVIRONMENT)) + path;
    }
}
