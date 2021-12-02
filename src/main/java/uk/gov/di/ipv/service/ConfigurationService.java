package uk.gov.di.ipv.service;

import java.util.Optional;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.dto.CredentialIssuers;
import uk.gov.di.ipv.helpers.CredentialIssuerLoader;

public class ConfigurationService {

    private static final long DEFAULT_BEARER_TOKEN_TTL_IN_SECS = 3600L;

    private final SSMProvider ssmProvider;

    public ConfigurationService(SSMProvider ssmProvider) {
        this.ssmProvider = ssmProvider;
    }

    public ConfigurationService() {
        this.ssmProvider = ParamManager.getSsmProvider();
    }

    public boolean isRunningLocally() {
        return Boolean.parseBoolean(System.getenv("IS_LOCAL"));
    }

    public String getAuthCodesTableName() {
        return System.getenv("AUTH_CODES_TABLE_NAME");
    }

    public CredentialIssuers getCredentialIssuers() {
        String value = ssmProvider.get("credentialIssuerConfig");
        return CredentialIssuerLoader.loadCredentialIssuers(value);
    }

    public String getUserIssuedCredentialTableName() {
        return System.getenv("USER_ISSUED_CREDENTIALS_TABLE_NAME");
    }

    public String getAccessTokensTableName() { return System.getenv("ACCESS_TOKENS_TABLE_NAME"); }

    public String getIpvSessionTableName() {
        return System.getenv("IPV_SESSIONS_TABLE_NAME");
    }

    public long getBearerAccessTokenTtl() {
        return Optional.of(System.getenv("BEARER_TOKEN_TTL"))
                .map(Long::valueOf)
                .orElse(DEFAULT_BEARER_TOKEN_TTL_IN_SECS);
    }

}
