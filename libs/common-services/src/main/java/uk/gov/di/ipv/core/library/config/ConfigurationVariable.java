package uk.gov.di.ipv.core.library.config;

public enum ConfigurationVariable {
    CIMIT_API_KEY("cimitApi/apiKey"),
    CREDENTIAL_ISSUER_CLIENT_OAUTH_SECRET("credentialIssuers/%s/connections/%s/oAuthClientSecret"),
    CREDENTIAL_ISSUER_API_KEY("credentialIssuers/%s/connections/%s/apiKey"),
    EVCS_API_KEY("evcs/apiKey"),
    JAR_ENCRYPTION_KEY_JWK("self/jarEncryptionKey"),
    SIGNING_KEY_JWK("self/signingKey");

    private final String path;

    ConfigurationVariable(String path) {

        this.path = path;
    }

    public String getPath() {
        return path;
    }
}
