package uk.gov.di.ipv.service;

public class ConfigurationService {

    private static final long DEFAULT_BEARER_TOKEN_TTL_IN_SECS = 3600L;

    private static ConfigurationService configurationService;

    public static ConfigurationService getInstance() {
        if (configurationService == null) {
            configurationService = new ConfigurationService();
        }
        return configurationService;
    }

    public boolean isRunningLocally() {
        return Boolean.parseBoolean(System.getenv("IS_LOCAL")) ;
    }

    public String getAuthCodesTableName() {
        return System.getenv("AUTH_CODES_TABLE_NAME");
    }

    public String getAccessTokensTableName() { return System.getenv("ACCESS_TOKENS_TABLE_NAME"); }

    public long getBearerAccessTokenTtl() {
        return System.getenv().containsKey("BEARER_TOKEN_TTL")
            ?  Long.parseLong(System.getenv("BEARER_TOKEN_TTL"))
            : DEFAULT_BEARER_TOKEN_TTL_IN_SECS;
    }
}
