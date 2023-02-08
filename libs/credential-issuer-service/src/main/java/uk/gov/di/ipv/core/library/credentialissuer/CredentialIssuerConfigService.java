package uk.gov.di.ipv.core.library.credentialissuer;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.ParseCredentialIssuerConfigException;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX;

public class CredentialIssuerConfigService extends ConfigService {

    public CredentialIssuerConfigService(SSMProvider ssmProvider, SecretsProvider secretsProvider) {
        super(ssmProvider, secretsProvider);
    }

    @ExcludeFromGeneratedCoverageReport
    public CredentialIssuerConfigService() {
        super();
    }

    private static final Logger LOGGER = LogManager.getLogger();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public CredentialIssuerConfig getCredentialIssuer(String credentialIssuerId) {
        Map<String, String> result =
                getSsmParameters(
                        String.format(
                                "%s/%s",
                                getEnvironmentVariable(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX),
                                credentialIssuerId));
        return new ObjectMapper().convertValue(result, CredentialIssuerConfig.class);
    }

    public List<uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig> getCredentialIssuers()
            throws ParseCredentialIssuerConfigException {
        Map<String, String> params =
                getSsmParameters(
                        getEnvironmentVariable(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX), true);

        Map<String, Map<String, Object>> map = new HashMap<>();
        for (Map.Entry<String, String> entry : params.entrySet()) {
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
                .map(
                        config ->
                                objectMapper.convertValue(
                                        config,
                                        uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig
                                                .class))
                .collect(Collectors.toList());
    }

    private String getAttributeNameFromParameter(Map.Entry<String, String> parameter)
            throws ParseCredentialIssuerConfigException {
        String[] splitKey =
                getSplitKey(
                        parameter,
                        "The attribute name cannot be parsed from the parameter path %s");
        return splitKey[1];
    }

    private String getCriIdFromParameter(Map.Entry<String, String> parameter)
            throws ParseCredentialIssuerConfigException {
        String[] splitKey =
                getSplitKey(
                        parameter,
                        "The credential issuer id cannot be parsed from the parameter path %s");
        return splitKey[0];
    }

    private String[] getSplitKey(Map.Entry<String, String> parameter, String message)
            throws ParseCredentialIssuerConfigException {
        String[] splitKey = parameter.getKey().split("/");
        if (splitKey.length < 2) {
            String errorMessage = String.format(message, parameter.getKey());
            LOGGER.error(errorMessage);
            throw new ParseCredentialIssuerConfigException(errorMessage);
        }
        return splitKey;
    }
}
