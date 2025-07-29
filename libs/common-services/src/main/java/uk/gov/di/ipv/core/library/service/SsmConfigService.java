package uk.gov.di.ipv.core.library.service;

import lombok.Getter;
import lombok.Setter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.DecryptionFailureException;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidParameterException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.ParameterNotFoundException;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static java.time.temporal.ChronoUnit.MINUTES;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CONFIG_SERVICE_CACHE_DURATION_MINUTES;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.ENVIRONMENT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_FEATURE_SET;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_PARAMETER_PATH;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_SECRET_ID;

public class SsmConfigService extends ConfigService {

    private static final String CORE_BASE_PATH = "/%s/core/";
    private static final int DEFAULT_CACHE_DURATION_MINUTES = 3;
    private static final Logger LOGGER = LogManager.getLogger();
    private final SSMProvider ssmProvider;
    private final SecretsProvider secretsProvider;

    @Getter @Setter private List<String> featureSet;

    public SsmConfigService(
            SSMProvider ssmProvider, SecretsProvider secretsProvider, List<String> featureSet) {
        this.ssmProvider = ssmProvider;
        this.secretsProvider = secretsProvider;
        setFeatureSet(featureSet);
    }

    public SsmConfigService(SSMProvider ssmProvider, SecretsProvider secretsProvider) {
        this(ssmProvider, secretsProvider, null);
    }

    @ExcludeFromGeneratedCoverageReport
    public SsmConfigService() {
        var cacheDuration =
                getIntegerEnvironmentVariable(
                        CONFIG_SERVICE_CACHE_DURATION_MINUTES, DEFAULT_CACHE_DURATION_MINUTES);

        this.ssmProvider =
                ParamManager.getSsmProvider(
                                SsmClient.builder()
                                        .httpClient(UrlConnectionHttpClient.create())
                                        .build())
                        .defaultMaxAge(cacheDuration, MINUTES);

        this.secretsProvider =
                ParamManager.getSecretsProvider(
                                SecretsManagerClient.builder()
                                        .httpClient(UrlConnectionHttpClient.create())
                                        .build())
                        .defaultMaxAge(cacheDuration, MINUTES);
    }

    @Override
    protected String getParameter(String path) {
        if (getFeatureSet() != null) {
            for (String fs : getFeatureSet()) {
                final Path featureSetPath = Path.of(resolveFeatureSetSsmPath(fs, path));
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
                                    .with(LOG_PARAMETER_PATH.getFieldName(), path)
                                    .with(LOG_FEATURE_SET.getFieldName(), fs));
                }
            }
        }

        try {
            return ssmProvider.get(resolvePath(path));
        } catch (ParameterNotFoundException e) {
            throw new ConfigParameterNotFoundException(path);
        }
    }

    @Override
    protected String getSecret(String path) {
        try {
            return secretsProvider.get(resolvePath(path));
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

    @Override
    protected boolean isConfigInYaml() {
        var basePath = "self/configFormat";
        try {
            var configFormat = ssmProvider.get(resolvePath(basePath));
            return configFormat.equals("yaml");
        } catch (ParameterNotFoundException e) {
            throw new ConfigParameterNotFoundException("Can not detect config format");
        }
    }

    @Override
    protected Map<String, String> getParametersByPrefix(String path) {
        return ssmProvider.getMultiple(resolvePath(path));
    }

    @Override
    protected Map<String, String> getParametersByPrefixYaml(String path) {
        var parameters = ssmProvider.recursive().getMultiple(resolvePath(path));
        if (parameters.isEmpty()) {
            throw new ConfigParameterNotFoundException("SSM parameter not found for path: " + path);
        }
        return parameters;
    }

    private String resolvePath(String path) {
        return String.format(CORE_BASE_PATH, getEnvironmentVariable(ENVIRONMENT)) + path;
    }

    private String resolveFeatureSetSsmPath(String featureSet, String path) {
        return resolvePath(String.format("features/%s/", featureSet) + path);
    }
}
