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
import software.amazon.lambda.powertools.parameters.AppConfigProvider;
import software.amazon.lambda.powertools.parameters.BaseProvider;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.exceptions.ConfigParseException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.temporal.ChronoUnit.MINUTES;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CONFIG_SERVICE_CACHE_DURATION_MINUTES;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.ENVIRONMENT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_SECRET_ID;

public class AppConfigService extends ConfigService {
    private static final Logger LOGGER = LogManager.getLogger(AppConfigService.class);
    private static final int DEFAULT_CACHE_DURATION_MINUTES = 3;
    private static final String CORE_BASE_PATH = "/%s/core/";

    @Getter @Setter private List<String> featureSet;
    private String paramsRawHash;
    private final BaseProvider appConfigProvider;
    private final SecretsProvider secretsProvider;

    @ExcludeFromGeneratedCoverageReport
    public AppConfigService() {
        var cacheDuration =
                getIntegerEnvironmentVariable(
                        CONFIG_SERVICE_CACHE_DURATION_MINUTES, DEFAULT_CACHE_DURATION_MINUTES);
        var applicationId = getEnvironmentVariable(EnvironmentVariable.APP_CONFIG_ID);
        var environmentId = getEnvironmentVariable(EnvironmentVariable.APP_CONFIG_ENVIRONMENT_ID);
        LOGGER.error(String.format("applicationId: %s, environmentId: %s", applicationId, environmentId));

        appConfigProvider =
                ParamManager.getAppConfigProvider(
                                AppConfigDataClient.builder()
                                        .httpClientBuilder(UrlConnectionHttpClient.builder())
                                        .build(),
                                environmentId,
                                applicationId)
                        .withMaxAge(cacheDuration, MINUTES);

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
        reloadParameters();
        return super.getParameter(path);
    }

    @Override
    public Map<String, String> getParametersByPrefix(String path) {
        reloadParameters();
        return super.getParametersByPrefix(path);
    }

    private void reloadParameters() {
        var profileId = getEnvironmentVariable(EnvironmentVariable.APP_CONFIG_PROFILE_ID);
        var paramsRaw = appConfigProvider.get(profileId);

        var retrievedParamsHash = getParamsRawHash(paramsRaw);
        if (!Objects.equals(paramsRawHash, retrievedParamsHash)) {
            setParameters(updateParameters(paramsRaw));
            paramsRawHash = retrievedParamsHash;
        }
    }

    private static String getParamsRawHash(String appConfigYaml) {
        try {
            var messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] digest = messageDigest.digest(appConfigYaml.getBytes(UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new ConfigParseException(e.getMessage());
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
