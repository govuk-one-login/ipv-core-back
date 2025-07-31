package uk.gov.di.ipv.core.library.config;

public enum ConfigurationVariable {
    AIS_API_BASE_URL("ais/apiBaseUrl"),
    AUTH_CODE_EXPIRY_SECONDS("self/authCodeExpirySeconds"),
    BACKEND_SESSION_TIMEOUT("self/backendSessionTimeout"),
    BACKEND_SESSION_TTL("self/backendSessionTtl"),
    BEARER_TOKEN_TTL("self/bearerTokenTtl"),
    CIMIT_COMPONENT_ID("cimit/componentId"),
    CIMIT_CONFIG("cimit/config"),
    CIMIT_SIGNING_KEY("cimit/signingKey"),
    CIMIT_API_BASE_URL("cimit/apiBaseUrl"),
    CIMIT_API_KEY("cimitApi/apiKey"),
    CI_CONFIG("self/ciConfig"),
    CI_SCORING_THRESHOLD("self/ciScoringThresholdByVot/%s"),
    CLIENT_ISSUER("clients/%s/issuer"),
    CLIENT_JWKS_URL("clients/%s/jwksUrl"),
    CLIENT_VALID_SCOPES("clients/%s/validScopes"),
    CLIENT_VALID_REDIRECT_URLS("clients/%s/validRedirectUrls"),
    COI_CHECK_FAMILY_NAME_CHARS("self/coi/familyNameChars"),
    COI_CHECK_GIVEN_NAME_CHARS("self/coi/givenNameChars"),
    COMPONENT_ID("self/componentId"),
    CORE_VTM_CLAIM("self/coreVtmClaim"),
    CREDENTIAL_ISSUER_ACTIVE_CONNECTION("credentialIssuers/%s/activeConnection"),
    CREDENTIAL_ISSUER_CONNECTION_PREFIX("credentialIssuers/%s/connections"),
    CREDENTIAL_ISSUER_CONFIG("credentialIssuers/%s/connections/%s"),
    CREDENTIAL_ISSUER_COMPONENT_ID("credentialIssuers/%s/connections/%s/componentId"),
    CREDENTIAL_ISSUER_ENABLED("credentialIssuers/%s/enabled"),
    CREDENTIAL_ISSUER_HISTORIC_SIGNING_KEYS("credentialIssuers/%s/historicSigningKeys"),
    CREDENTIAL_ISSUER_SHARED_ATTRIBUTES("credentialIssuers/%s/allowedSharedAttributes"),
    CREDENTIAL_ISSUER_CLIENT_OAUTH_SECRET("credentialIssuers/%s/connections/%s/oAuthClientSecret"),
    CREDENTIAL_ISSUER_API_KEY("credentialIssuers/%s/connections/%s/apiKey"),
    CRI_RESPONSE_TTL("self/criResponseTtl"),
    EVCS_API_KEY("evcs/apiKey"),
    EVCS_APPLICATION_URL("evcs/applicationUrl"),
    FEATURE_FLAGS("featureFlags/%s"),
    FRAUD_CHECK_EXPIRY_PERIOD_HOURS("self/fraudCheckExpiryPeriodHours"),
    CLIENT_JAR_KMS_ENCRYPTION_KEY_ALIAS_PRIMARY("self/clientJarKmsEncryptionKeyAliasPrimary"),
    CLIENT_JAR_KMS_ENCRYPTION_KEY_ALIAS_SECONDARY("self/clientJarKmsEncryptionKeyAliasSecondary"),
    JAR_ENCRYPTION_KEY_JWK("self/jarEncryptionKey"),
    JWT_TTL_SECONDS("self/jwtTtlSeconds"),
    MAX_ALLOWED_AUTH_CLIENT_TTL("self/maxAllowedAuthClientTtl"),
    OAUTH_KEY_CACHE_DURATION_MINS("self/oauthKeyCacheDurationMins"),
    PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY("clients/%s/publicKeyMaterialForCoreToVerify"),
    RETURN_CODES_ALWAYS_REQUIRED("self/returnCodes/alwaysRequired"),
    RETURN_CODES_NON_CI_BREACHING_P0("self/returnCodes/nonCiBreachingP0"),
    SESSION_CREDENTIALS_TTL("self/sessionCredentialTtl"),
    SIGNING_KEY_ID("self/signingKeyId"),
    SIGNING_KEY_JWK("self/signingKey"),
    STORED_IDENTITY_SERVICE_COMPONENT_ID("storedIdentityService/componentId"),
    DCMAW_ASYNC_VC_PENDING_RETURN_TTL("self/dcmawAsyncVcPendingReturnTtl");

    private final String path;

    ConfigurationVariable(String path) {

        this.path = path;
    }

    public String getPath() {
        return path;
    }
}
