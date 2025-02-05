package uk.gov.di.ipv.core.library.service;

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
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.io.IOException;
import java.util.List;

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
    private final SecretsProvider secretsProvider;

    public AppConfigService() {
        var cacheDuration =
                getEnvironmentVariable(
                        CONFIG_SERVICE_CACHE_DURATION_MINUTES, DEFAULT_CACHE_DURATION_MINUTES);
        var paramsRaw = getRawParams(cacheDuration);

        initializeConfig(paramsRaw);
        this.secretsProvider =
                ParamManager.getSecretsProvider(
                                SecretsManagerClient.builder()
                                        .httpClient(UrlConnectionHttpClient.create())
                                        .build())
                        .defaultMaxAge(cacheDuration, MINUTES);
    }

    public AppConfigService(String paramsRaw, SecretsProvider secretsProvider) {
        initializeConfig(paramsRaw);
        this.secretsProvider = secretsProvider;
    }

    private void initializeConfig(String paramsRaw) {
        try {
            var paramsYaml = YAML_OBJECT_MAPPER.readTree(paramsRaw).get(CORE);
            addJsonConfig(parameters, paramsYaml);
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not load parameter yaml", e);
        }
    }

    private String getRawParams(Integer cacheDuration) {
        var applicationId = getEnvironmentVariable(EnvironmentVariable.APP_CONFIG_ID);
        var environmentId = getEnvironmentVariable(EnvironmentVariable.APP_CONFIG_ENVIRONMENT_ID);
        var profileId = getEnvironmentVariable(EnvironmentVariable.APP_CONFIG_PROFILE_ID);

        return ParamManager.getAppConfigProvider(
                        AppConfigDataClient.builder()
                                .httpClient(UrlConnectionHttpClient.create())
                                .build(),
                        environmentId,
                        applicationId)
                .withMaxAge(cacheDuration, MINUTES)
                .get(profileId);
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
        } catch (InvalidParameterException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            String.format(
                                    "An invalid value was provided for the param value: %s", path),
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
                            .with(LOG_SECRET_ID.getFieldName(), path));
        }
        return null;
    }

    private String resolveSecretPath(String path) {
        return String.format(CORE_BASE_PATH, getEnvironmentVariable(ENVIRONMENT)) + path;
    }
}
